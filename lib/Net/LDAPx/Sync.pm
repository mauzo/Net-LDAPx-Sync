package Net::LDAPx::Sync;

=head1 NAME

Net::LDAPx::Sync - Perform an RFC 4533 sync operation with an LDAP server

=head1 SYNOPSIS

    use Net::LDAP;
    use Net::LDAPx::Sync;

    my $LDAP = Net::LDAP->new(...);
    my $sync = Net::LDAPx::Sync->new(
        LDAP        => $LDAP,
        cache       => 1,
        callback    => sub {...},
    );

    $sync->start_sync(
        base    => ...,
        filter  => ...,
        persist => 1,
    );
    $sync->wait_for_sync;

    process_results $sync->results;
    write_to_file $sync->freeze;

=head1 DESCRIPTION

A C<Net::LDAPx::Sync> object represents an RFC 4533 Sync Session with an
LDAP server. This LDAP extension provides a way to keep an up-to-date
local cache of the results of a search, including immediate notification
of changes while the sync operation is active. It is possible to save
the results of the search to a file and restart the sync later without
retransferring the data already received.

=cut

use Moo;
no warnings "uninitialized";

use Carp;
use Data::Dump  qw/pp/;
use Data::UUID;
use Try::Tiny;

use Net::LDAP;
use Net::LDAP::Constant qw[
    LDAP_SUCCESS LDAP_CANCELED
    LDAP_SYNC_REFRESH_ONLY LDAP_SYNC_REFRESH_AND_PERSIST
    LDAP_SYNC_ADD LDAP_SYNC_MODIFY LDAP_SYNC_DELETE LDAP_SYNC_PRESENT
    LDAP_CONTROL_SYNC_STATE LDAP_CONTROL_SYNC_DONE
];
use Net::LDAP::Extension::Cancel;
use Net::LDAP::Control::SyncRequest;

our $VERSION = "0";

with "MooX::Role::WeakClosure";

=head1 ATTRIBUTES

C<Net::LDAPx::Sync> is build using L<Moo>, so attributes can be passed
to the constructor as either a hash or a hashref, and accessed with
accessor methods. Most are read-only, at least publically.

=head2 LDAP

A L<Net::LDAP> object to use to communicate with the LDAP server.

=cut

has LDAP        => is => "ro";

=head2 callback

A subref to be called when new entries arrive in the persist stage of a
refreshAndPersist sync session. This attribute is read-write.

=cut

has callback    => is => "rw";

=head2 cookie

The most recent cookie returned from the server for this search. If the
C<Sync> object is caching results it's important that this cookie
correctly corresponds to the state of the cache.

=cut

has cookie      => is => "rw", trigger => 1;

=head2 state

This returns the current state of the sync session, one of C<idle>,
C<refresh> or C<persist>. C<idle> means the object currently has no
search active. See the RFC for the details of the refresh and persist
stages of the sync search.

This attribute cannot be set in the constructor; C<Sync> objects always
start in the C<idle> state.

=cut

has state       => is => "rwp", default => "idle", init_arg => undef;

=for private
search      the currently-active search, if any,
cache       our local results cache, keyed by entryUUID.
_present    used in the 'present' phase to record entries still present.

=cut

has search      => is => "rw", predicate => 1, clearer => 1;
has cache       => is => "ro", predicate => 1;
has _present    => (
    is          => "ro",
    lazy        => 1,
    default     => sub { +{} },
    predicate   => 1,
    clearer     => 1,
);

=head1 METHODS

=head2 new

    my $sync = Net::LDAPx::Sync->new(%atts);

This is the constructor. In addition to the attributes listed above, the
following keys can be passed:

=over 4

=item cache

Specifies whether the C<Sync> object should maintain an internal cache
of the results of the search. If C<1> is passed a private hashref will
be used. Alternatively, a hashref can be passed, and the C<Sync> object
will use that. The hash contains L<Net::LDAP::Entry> objects, and is
keyed by C<entryUUID>.

=item thaw

This should specify a data structure returned from L</freeze> on a
C<Sync> object referencing the same search on the same server. It will
build a new object which will continue the same sync session.

=back

=cut

sub BUILDARGS {
    my ($class, @args) = @_;
    my $args = @args == 1 ? $args[0] : { @args };

    $$args{thaw} and $class->_thaw($args);

    $$args{cache} && !ref $$args{cache} 
        and $$args{cache} = {};

    $args;
}

# I think someone doesn't understand what objects are for...
my $UUID = Data::UUID->new;

sub info {
    my ($fmt, @args) = @_;
    my $str = @args ? sprintf $fmt, @args : $fmt;
    warn "$str\n";
}

sub _maybe_cookie {
    my ($self, $ck) = @_;
    $ck and $self->cookie($ck);
}

sub _trigger_cookie {
    my ($self, $new) = @_;
    info "NEW COOKIE [$new]";
}

sub update_cookie {
    my ($self, $from) = @_;
    $from or return;

    my ($ck, $control);
    if ($from->isa("Net::LDAP::Message")) {
        $control and $ck = $control->cookie;
    }
    elsif ($from->isa("Net::LDAP::Intermediate::SyncInfo")) {
    }
    if ($ck) {
        info "COOKIE [$from] [$ck]";
        $self->cookie($ck);
    }
    $control;
}

sub _trigger_state {
    my ($self, $state) = @_;

    $state eq "refresh" and $self->_clear_present;
}

sub _process_present {
    my ($self) = @_;

    my $c = $self->cache;
    unless ($self->_has_present) {
        info "NO ENTRIES PRESENT";
        %$c = ();
        return;
    }

    my $p = $self->_present;
    for (keys %$c) {
        $$p{$_} and next;
        my $uua = $UUID->to_string($_);
        info "NOT PRESENT [$uua]"; 
        delete $$c{$_};
    }
    $self->_clear_present;
}

sub _handle_entry {
    my ($self, $entry, $from) = @_;

    my $control = $from->control(LDAP_CONTROL_SYNC_STATE)
        or return;
    $self->_maybe_cookie($control->cookie);

    $self->has_cache and $self->_handle_cache_entry($entry, $control);

    return $control;
}

sub _handle_cache_entry {
    my ($self, $entry, $control) = @_;

    my $c   = $self->cache;
    my $st  = $control->state;
    my $uu  = $control->entryUUID;
    my $uua = $UUID->to_string($uu);
    
    if ($st == LDAP_SYNC_ADD || $st == LDAP_SYNC_MODIFY) {
        $$c{$uu} = $entry;
        info "ADD/MOD [%s] [%s]", $uua, $entry->dn;
    }
    elsif ($st == LDAP_SYNC_DELETE) {
        my $entry = delete $$c{$uu};
        info "DELETE [%s] [%s]", $uua, $entry->dn;
    }
    elsif ($st == LDAP_SYNC_PRESENT) {
        $self->_present->{$uu} = 1;
        info "PRESENT [%s] [%s]", $uua, $$c{$uu}->dn;
    }
    else {
        die "Unknown sync info state [$st]";
    }
}

# Sync Info is sent in the following circumstances:
#
#   - newcookie may be sent at any time, and just updates the cookie.
#
#   - syncIdSet may be sent at any time, and are equivalent to some set
#     of SYNC_PRESENT or SYNC_DELETE entry results. refreshDeletes says
#     which.
#
#   - refreshPresent and refreshDelete are sent at the end of each phase
#     of the refresh stage, if this is not the end of the whole search.
#     Which is sent indicates which phase has just ended. This matters
#     because a 'present' phase with no SYNC_PRESENT results should
#     clear the cache. refreshDone indicates whether we have entered a
#     new phase of refresh or moved onto the persist stage.

sub _handle_info {
    my ($self, $info) = @_;

    my $ck  = $info->newcookie;
    my $asn = $info->{asn};

    info "SYNC INFO: " . pp $asn;

    if (my $set = $$asn{syncIdSet}) {
        $ck     = $$set{cookie};
        my $uus = $$set{syncUUIDs};

        if ($$set{refreshDeletes}) {
            my $c = $self->cache;
            delete $$c{$_} for @$uus;
        }
        else {
            my $p = $self->_present;
            $$p{$_} = 1 for @$uus;
        }
    }
    elsif (my $end = $$asn{refreshPresent} // $$asn{refreshDelete}) {
        $$asn{refreshPresent} and $self->_process_present;
        $ck = $$end{cookie};
        $$end{refreshDone} and $self->_set_state("persist");
    }

    $self->_maybe_cookie($ck);
}

=head2 results

    my @results = $sync->results;

Returns the currently cached results of the search, as updated by the
sync operation. This method should only be called if the C<Sync> object
has a cache.

=cut

sub results {
    my ($self) = @_;
    my $cache = $self->cache;
    values %$cache;
}

=head2 freeze

    my $data = $sync->freeze;

Freezes the current state of the cache and the current cookie into a
plain Perl data structure, which can be written out to a file and used
to resume the sync session later. The data structure should be
considered opaque, but it will contain no objects and no circular refs,
so it is suitable for serializing as JSON or YAML.

=cut

my $FreezeVersion = 1;

sub freeze {
    my ($self) = @_;
    my $cache = $self->cache or return;

    return {
        version     => $FreezeVersion,
        cookie      => $self->cookie,
        cache       => {
            map {
                my $e = $$cache{$_};
                (   $UUID->to_string($_),
                    [   $e->dn,
                        map +($_, [$e->get_value($_)]),
                            $e->attributes,
                    ],
                );
            } keys %$cache,
        },
    };
}

# class method, called from BUILDARGS
sub _thaw {
    my ($class, $args) = @_;
    
    my $data    = $$args{thaw};
    my $vers    = $$data{version};
    my $meth    = $class->can("_thaw_$vers")
        or croak "Unknown freeze version [$vers]";

    $class->$meth($data, $args);
}

sub _thaw_1 {
    my ($class, $data, $args) = @_;

    require Net::LDAP::Entry;

    $$args{cookie}  = $$data{cookie};

    my $cache       = $$data{cache};
    $$args{cache}   = {
        map +(
            $UUID->from_string($_),
            Net::LDAP::Entry->new(@{$$cache{$_}}),
        ), keys %$cache,
    };
}

sub _do_callback {
    my ($self, $srch, $res, $ref) = @_;
    info "CALLBACK [$res]";

    if (!$res) { return }
    elsif ($res->isa("Net::LDAP::Entry")) {
        my $control = $self->_handle_entry($res, $srch);
        $self->state eq "persist"
            and $self->callback->($srch, $res, $ref, $control)
            and $self->stop_sync;
    }
    elsif ($res->isa("Net::LDAP::Intermediate::SyncInfo")) {
        $self->_handle_info($res);
    }
    else {
        info "UNKNOWN RESULT [$res]";
    }
}

=head2 start_sync

    my $search = $sync->start_sync(
        base    => ...,
        filter  => ...,
        persist => 1,
    );

Start a sync search, moving the C<Sync> object from state C<idle> to
C<refresh>. The C<persist> parameter controls whether this is a
persistent search: if it is false, the search will retrieve any changed
entries, update the cache if any, and finish; if it is true, the search
will continue after the refresh phase waiting for the server to send
down changes as they happen. If the search enters the C<persist> phase,
it will not finish until either the L</stop_sync> method is called or
the server chooses to terminate it. 

Returns a L<Net::LDAP::Search> object representing the search in
progress. If the C<Net::LDAP> object we are using is in C<async> mode,
it will return as soon as the search has been sent to the server,
without waiting for results. Use the L</sync_done> and L</wait_for_sync>
methods to determine when the search has finished. Otherwise, it will
not return until the search has finished, which for C<< persist => 1 >>
searches will not usually happen until L</stop_sync> is called.

It is necessary to call the L</sync_done> method once the search has
finished, to finish the internal bookkeeping.
             
=cut

sub start_sync {
    my ($self, %params) = @_;

    $self->has_search and croak "[$self] already has a search";

    my $L       = $self->LDAP;
    my $persist = delete $params{persist} // 1;

    my $req = Net::LDAP::Control::SyncRequest->new(
        critical    => 1,
        mode        => ($persist ? LDAP_SYNC_REFRESH_AND_PERSIST
                            : LDAP_SYNC_REFRESH_ONLY),
        cookie      => $self->cookie,
    );

    info "STARTING SEARCH [$req]";
    my $srch = $L->search(
        %params,
        callback    => $self->weak_method("_do_callback"),
        control     => [$req],
    );
    info "SEARCH STARTED [$srch]";
    $self->_set_state("refresh");
    $self->search($srch);
    $srch;
}

sub _search { 
    my ($self) = @_;
    $self->state eq "idle"
        and croak "[$self] is not currently syncing";
    $self->search;
}

=head2 wait_for_sync

    my $cookie = $sync->wait_for_sync;

Waits for a currently-active sync search to finish, and returns the
final cookie from the server (if any). Throws an exception if we are not
currently searching. This will call L</sync_done> for you.

=cut

sub wait_for_sync {
    my ($self) = @_;

    my $srch = $self->_search;
    info "WAIT FOR [$srch]";
    $srch->sync;
    $self->sync_done;
}

=head2 sync_done

    my $done = $sync->sync_done;

Returns the most recent cookie from the server if the search has
finished. If it has not, returns the empty list without blocking.

=cut

sub sync_done {
    my ($self) = @_;

    my $srch = $self->_search;
    $srch->done or return;

    info "SEARCH FINISHED";
    $self->clear_search;

    die sprintf "[$srch]: LDAP error: %s [%d] (%s)",
        $srch->error, $srch->code, $@
        unless $srch->code == LDAP_SUCCESS ||
            $srch->code == LDAP_CANCELED;

    if (my $control = $srch->control(LDAP_CONTROL_SYNC_DONE)) {
        $self->_maybe_cookie($control->cookie);
        $control->refreshDeletes or $self->_process_present;
    }
    $self->_set_state("idle");

    return $self->cookie;
}

=head2 stop_sync

    $sync->stop_sync;

Sends a LDAP Cancel operation to cancel an in-progress sync search. This is normally the only way of stopping a refreshAndPersist search.

=cut

sub stop_sync {
    my ($self) = @_;
    my $srch = $self->_search;
    info "CANCEL SEARCH [$srch]";
    my $cancel = $self->LDAP->cancel($srch);
    $cancel->control(LDAP_CONTROL_SYNC_DONE)
        and info "GOT A SyncDone FROM A CANCEL";
    $cancel;
}

1;

=head1 SEE ALSO

L<Net::LDAP>, RFC 4533.

=head1 BUGS

Please report any bugs to <bug-Net-LDAPx-Sync@rt.cpan.org>.

=head1 AUTHOR

Ben Morrow <ben@morrow.me.uk>

=head1 COPYRIGHT

Copyright 2014 Ben Morrow.

Released under the 2-clause BSD licence.

