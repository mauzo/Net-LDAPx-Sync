package Net::LDAPx::Sync;

=head1 NAME

Net::LDAPx::Sync - Perform an RFC 4533 LDAP sync

=head1 SYNOPSIS

    use Net::LDAP;
    use Net::LDAPx::Sync;

    my $sync = Net::LDAPx::Sync->new(
        LDAP        => Net::LDAP->new(...),
        cache       => 1,
        search      => { base => ..., filter => ... }
        callbacks   => { change => sub { ... } },
    );
    $sync->sync;

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
use Clone           qw/clone/;
use Data::Compare;  # exports Compare
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

=head2 cookie

The most recent cookie returned from the server for this search. If the
C<Sync> object is caching results it's important that this cookie
correctly corresponds to the state of the cache.

=cut

has cookie      => is => "rw", trigger => 1;

=head2 search

A hashref of parameters to pass to C<< Net::LDAP->search >> to initiate
the sync search.

=cut

has search      => is => "ro";

=head2 state

This returns the current state of the sync session, one of C<idle>,
C<refresh> or C<persist>. C<idle> means the object currently has no
search active. See the RFC for the details of the refresh and persist
stages of the sync search.

This attribute cannot be set in the constructor; C<Sync> objects always
start in the C<idle> state.

=cut

has state => (
    is          => "rwp", 
    default     => "idle", 
    init_arg    => undef,
    trigger     => 1,
);

=for private
cache       our local results cache, keyed by entryUUID.
callbacks   hashref of callback subs
dirty       indicates if there are changes we haven't sent 'change' for
present     used in the 'present' phase to record entries still present.
search      the currently-active search, if any,

=cut

has _cache      => is => "ro", predicate => 1, init_arg => "cache";
has _callbacks  => (
    is          => "ro",
    lazy        => 1,
    default     => sub { +{} },
    init_arg => "callbacks",
);
has _dirty      => is => "rw", default => 0, init_arg => undef;
has _present    => (
    is          => "ro",
    lazy        => 1,
    default     => sub { +{} },
    predicate   => 1,
    clearer     => 1,
);
has _search     => is => "rw", clearer => 1;

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

=item callbacks

Specifies a hashref of callbacks. The hashref passed may be modified, so
don't share it with other objects. See L</CALLBACKS> for valid keys.

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
    my $msg = @args ? sprintf $fmt, @args : $fmt;
    warn "$msg\n";
}

sub panic {
    my ($self, $fmt, @args);
    my $msg = @args ? sprintf $fmt, @args : $fmt;
    die "Internal error: [$self]: $msg\n";
}

sub _maybe_cookie {
    my ($self, $ck) = @_;
    $ck and $self->cookie($ck);
}

sub _trigger_cookie {
    my ($self, $new) = @_;
    info "NEW COOKIE [$new]";
    $self->_callback("cookie", $new);
}

sub _trigger_state {
    my ($self, $state) = @_;

    info "STATE CHANGE [$state]";
    $state eq "refresh" and $self->_clear_present;
    $state eq "starting" or $self->_callback($state);

    if ($self->_dirty) {
        $self->_dirty(0);
        $self->_callback("change");
    }
}

sub _dirtify {
    my ($self) = @_;
    if ($self->state eq "persist") {
        $self->_callback("change");
    }
    else {
        $self->_dirty(1);
    }
}

sub _process_present {
    my ($self) = @_;

    my $c   = $self->_cache;
    my $cb  = $self->_has_callback("delete");
    unless ($self->_has_present) {
        info "NO ENTRIES PRESENT";
        my %old = $cb ? %$c : ();
        %$c = ();
        if (%old) {
            $self->$cb($old{$_}, $_) for keys %old;
        }
        return;
    }

    my $p = $self->_present;
    for (keys %$c) {
        $$p{$_} and next;
        my $uua = $UUID->to_string($_);
        info "NOT PRESENT [$uua]"; 
        my $old = delete $$c{$_};
        $cb and $self->$cb($old, $_);
    }
    $self->_clear_present;
    $self->_dirtify;
}

sub _handle_search {
    my ($self, $srch) = @_;

    my $st = $self->state;
    my $cl = (caller 1)[3];
    info "HANDLE SEARCH [$st] FROM [$cl]";

    if ($st eq "starting") {
        info "SEARCH STARTED [$srch]";
        $self->_search($srch);
        $self->_set_state("refresh");
    }

    $st ne "idle" && $srch->done 
        and $self->_sync_done;
}

sub _handle_change {
    my ($self, $type, $uuid, $new) = @_;

    my $c   = $self->_cache;
    my $old = $$c{$uuid};

    my @args;
    for ($type) {
        /add/       and @args = $$c{$uuid} = $new;
        /modify/    and @args = ($$c{$uuid}, $new), $$c{$uuid} = $new;
        /delete/    and @args = delete $$c{$uuid};
        /present/   and $self->_present->{$uuid} = 1;
    }
    info "%s [%s]%s", uc $type, $UUID->to_string($uuid),
        join "", map " [$_]", map $_->dn, @args;

    @args and $self->_callback($type, @args);
}

sub _handle_entry {
    my ($self, $entry, $from) = @_;

    my $control = $from->control(LDAP_CONTROL_SYNC_STATE)
        or return;
    $self->_maybe_cookie($control->cookie);

    my $st  = $control->state;
    my $typ = (qw/present add modify delete/)[$st]
        or $self->panic("Unknown sync state [$st]");
    my $uu  = $control->entryUUID;

    $self->_handle_change($typ, $uu, $entry);
    $self->_dirtify;

    return $control;
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

    if (my $set = $$asn{syncIdSet}) {
        $ck     = $$set{cookie};
        my $uus = $$set{syncUUIDs};
        my $typ = $$set{refreshDeletes} ? "delete" : "present";

        $self->_handle_change($typ, $_) for @$uus;
        $self->_dirtify;
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
    my $cache = $self->_cache;
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

my $FreezeVersion = 2;

sub freeze {
    my ($self) = @_;
    my $cache = $self->_cache or return;

    return {
        version     => $FreezeVersion,
        search      => clone($self->search),
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

sub _thaw_2 {
    my ($class, $data, $args) = @_;

    $class->_thaw_1($data, $args);

    my $new = $$data{search} or return;
    if (my $old = $$args{search}) {
        unless (Compare $old, $new) {
            info "SEARCH PARAMS DIFFER, DISCARDING CACHE";
            delete $$args{cookie};
            exists $$args{cache} and %{$$args{cache}} = ();
        }
    }
    else {
        $$args{search} = $new;
    }
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

sub _ldap_callback {
    my ($self, $srch, $res, $ref) = @_;
    my $st = $self->state;
    info "CALLBACK [$st] [$res]";

    $self->_handle_search($srch);

    if (!$res) { return }
    elsif ($res->isa("Net::LDAP::Entry")) {
        my $control = $self->_handle_entry($res, $srch);
    }
    elsif ($res->isa("Net::LDAP::Intermediate::SyncInfo")) {
        $self->_handle_info($res);
    }
    else {
        info "UNKNOWN RESULT [$res]";
    }
}

=head2 sync

    my $search = $sync->sync(persist => 1);

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

=cut

sub sync {
    my ($self, %params) = @_;

    $self->state eq "idle" or croak "[$self] is already syncing";

    my $L       = $self->LDAP;
    my $persist = delete $params{persist};

    my $req = Net::LDAP::Control::SyncRequest->new(
        critical    => 1,
        mode        => ($persist ? LDAP_SYNC_REFRESH_AND_PERSIST
                            : LDAP_SYNC_REFRESH_ONLY),
        cookie      => $self->cookie,
    );

    info "STARTING SEARCH [$req]";
    $self->_set_state("starting");
    my $srch = $L->search(
        %{$self->search},
        callback    => $self->weak_method("_ldap_callback"),
        control     => [$req],
    );
    $self->_handle_search($srch);
    $srch;
}

=head2 wait_for_idle

    $sync->wait_for_idle;

Wait until the sync session returns to the C<idle> state. If a search is
currently active this will block until it has finished.

=cut

sub wait_for_idle {
    my ($self) = @_;

    $self->state eq "idle" and return;
    my $srch = $self->_search
        or $self->panic("wait_for_idle called with no search");
    info "WAIT FOR [$srch]";
    $srch->sync;
}

sub _sync_done {
    my ($self) = @_;

    my $srch = $self->_clear_search;
    info "SEARCH FINISHED [$srch]";

    die sprintf "[$srch]: LDAP error: %s [%d] (%s)",
        $srch->error, $srch->code, $@
        unless $srch->code == LDAP_SUCCESS ||
            $srch->code == LDAP_CANCELED;

    if (my $control = $srch->control(LDAP_CONTROL_SYNC_DONE)) {
        $self->_maybe_cookie($control->cookie);
        $control->refreshDeletes or $self->_process_present;
    }
    $self->_set_state("idle");
}

=head2 stop_sync

    my $cancel = $sync->stop_sync;

Sends a LDAP Cancel operation to cancel an in-progress sync search. This
is normally the only way of stopping a refreshAndPersist search. Returns
a L<Net::LDAP::Message> representing the Cancel request.

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

=head1 CALLBACKS

The C<Sync> constructor can specify several callbacks to be called when
specific events occur. These callbacks can also, if you prefer, be
implemented by subclassing C<Sync> and creating them as methods; in this
case the method name is a callback name from the list below prefixed
with C<on_>. Callbacks passed to the constructor will override callbacks
specified as methods.

Valid callbacks are listed below, with an example in method call syntax
showing how they are called. Callbacks specified as subrefs are still
called in method form, so the C<Sync> object will be passed as the first
parameter. If the callback is a closure you should make use of this
parameter rather than allowing it to close over the C<Sync> object, to
avoid a reference loop.

=over 4

=item add

    $sync->on_add($entry, $uuid);

Called when the server reports a new entry has been added to the
results. This includes the initial content fetch for a sync search with
no starting cookie. C<$entry> is the new entry (or reference), C<$uuid>
is its C<entryUUID>, in binary form.

=item delete

    $sync->on_delete($entry, $uuid);

Called when the server reports an entry has been deleted. C<$entry> will
only be available if the C<Sync> object is using a cache; otherwise,
C<undef> will be passed.

=item modify

    $sync->on_modify($old, $new, $uuid);

Called when the server reports and entry has been modified. C<$old> and
C<$new> are the old and new versions of the entry; C<$old> will only be
passed if the C<Sync> object is using a cache.

=item cookie

    $sync->on_cookie($cookie);

Called when the server sends a new cookie.

=item change

    $sync->on_change;

Called once at the end of the refresh stage if the server returned any
changes at all; called again during the persist stage (if any) every
time a new changed entry is returned. This will be called after
C<add>/C<modify>/C<delete>.

=item idle

=item refresh

=item persist

    $sync->on_refresh;

Called when the C<Sync> object changes state. (Note that the internal
C<starting> state has no callback, since you should never see it.)

=back

=cut

sub _has_callback {
    my ($self, $which) = @_;

    $self->_callbacks->{$which} ||= $self->can("on_which");
}

sub _callback {
    my ($self, $which, @args) = @_;

    my $cb = $self->_has_callback($which) or return;
    $self->$cb(@args);
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

