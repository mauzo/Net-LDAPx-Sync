package Net::LDAPx::Sync;

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

has LDAP        => is => "ro";
has callback    => is => "rw";
has cookie      => is => "rw", trigger => 1;

has search      => is => "rw", predicate => 1, clearer => 1;
has cache       => is => "ro", predicate => 1;
has state       => is => "rwp", default => "idle";
has _present    => (
    is          => "ro",
    lazy        => 1,
    default     => sub { +{} },
    predicate   => 1,
    clearer     => 1,
);

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

sub info { warn "$_[0]\n" }

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

sub _change_state {
    my ($self, $new) = @_;
    my $old = $self->state;

    info "STATE CHANGE [$old] -> [$new]";

    if ($old eq "refresh" 
        && $self->_has_present
        && $self->has_cache
    ) {
        my $p = $self->_present;
        my $c = $self->cache;
        $$p{$_} or do { 
            my $uua = $UUID->to_string($_);
            info "NOT PRESENT [$uua]"; 
            delete $$c{$_};
        } for keys %$c;
        $self->_clear_present;
    }

    if ($new eq "refresh") {
        $self->_clear_present;
    }

    $self->_set_state($new);
}

sub _handle_entry {
    my ($self, $entry, $from) = @_;

    my $control = $from->control(
        LDAP_CONTROL_SYNC_STATE, LDAP_CONTROL_SYNC_DONE,
    ) or return;

    if (my $ck = $control->cookie) {
        $self->cookie($ck);
    }

    $self->has_cache and $self->_handle_cache_entry($entry, $control);

    return $control;
}

sub _handle_cache_entry {
    my ($self, $entry, $control) = @_;

    my $st  = $control->state;
    my $uu  = $control->entryUUID;
    my $uua = $UUID->to_string($uu);

    if ($st == LDAP_SYNC_ADD || $st == LDAP_SYNC_MODIFY) {
        info "ADD/MOD [$uua] [@{[$entry->dn]}]";
        $self->cache->{$uu} = $entry;
    }
    elsif ($st == LDAP_SYNC_DELETE) {
        info "DELETE [$uua] [@{[$self->cache->{$uu}->dn]}]";
        delete $self->cache->{$uu};
    }
    elsif ($st == LDAP_SYNC_PRESENT) {
        info "PRESENT [$uua] [@{[$self->cache->{$uu}->dn]}]";
        $self->_present->{$uu} = 1;
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
#     Which is sent indicates which phase has just ended (I don't care).
#     refreshDone indicates whether we have entered a new phase of refresh
#     or moved onto the persist stage.

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
        $ck = $$end{cookie};
        $$end{refreshDone} and $self->_change_state("persist");
    }

    $ck and $self->cookie($ck);
}

sub results {
    my ($self) = @_;
    my $cache = $self->cache;
    values %$cache;
}

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

sub start_sync {
    my ($self, $desc, %params) = @_;

    $self->has_search and croak "[$self] already has a search";

    my $L       = $self->LDAP;
    my $persist = delete $params{persist} // 1;
    my $cb      = delete $params{callback};

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
    $self->_change_state("refresh");
    $self->search($srch);
    $srch;
}

sub _search { 
    my ($self) = @_;
    $self->state eq "idle"
        and croak "[$self] is not currently syncing";
    $self->search;
}

sub wait_for_sync {
    my ($self) = @_;

    my $srch = $self->_search;
    info "WAIT FOR [$srch]";
    $srch->sync;
    $self->sync_done;
}

sub sync_done {
    my ($self) = @_;

    my $srch = $self->_search;
    $srch->done or return;

    $self->_change_state("idle");

    die sprintf "[$srch]: LDAP error: %s [%d] (%s)",
        $srch->error, $srch->code, $@
        unless $srch->code == LDAP_SUCCESS ||
            $srch->code == LDAP_CANCELED;
    info "SEARCH FINISHED";

    $self->update_cookie($srch);
    $self->clear_search;
    return $self->cookie;
}

sub stop_sync {
    my ($self) = @_;
    my $srch = $self->_search;
    info "CANCEL SEARCH [$srch]";
    $self->update_cookie($self->LDAP->cancel($srch));
}

1;
