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
    LDAP_SYNC_ADD LDAP_SYNC_MODIFY LDAP_SYNC_DELETE
    LDAP_CONTROL_SYNC_STATE LDAP_CONTROL_SYNC_DONE
];
use Net::LDAP::Extension::Cancel;
use Net::LDAP::Control::SyncRequest;

our $VERSION = "0";

with "MooX::Role::WeakClosure";

has LDAP        => is => "ro";
has callback    => is => "rw";
has cookie      => is => "rw";

has search      => is => "rw", predicate => 1, clearer => 1;
has cache       => is => "ro", predicate => 1;

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

sub update_cookie {
    my ($self, $from) = @_;
    $from or return;

    my ($ck, $control);
    if ($from->isa("Net::LDAP::Message")) {
        $control = $from->control(
            LDAP_CONTROL_SYNC_STATE, LDAP_CONTROL_SYNC_DONE,
        );
        $control and $ck = $control->cookie;
    }
    elsif ($from->isa("Net::LDAP::Intermediate::SyncInfo")) {
        $ck = $from->newcookie
            // $from->{asn}{refreshDelete}{cookie}
            // $from->{asn}{refreshPresent}{cookie}
            // $from->{asn}{syncIdSet}{cookie};
    }
    if ($ck) {
        info "COOKIE [$from] [$ck]";
        $self->cookie($ck);
    }
    $control;
}

sub update_cache {
    my ($self, $entry, $control) = @_;
    my $cache = $self->cache;

    my $st = $control->state;
    my $uu = $control->entryUUID;
    if ($st == LDAP_SYNC_ADD || $st == LDAP_SYNC_MODIFY) {
        $$cache{$uu} = $entry;
    }
    elsif ($st == LDAP_SYNC_DELETE) {
        delete $$cache{$uu};
    }
    else {
        # PRESENT
        die "Unknown sync info state [$st]";
    }
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
    my ($self, $srch, $entry, $ref) = @_;
    info "CALLBACK [$entry]";
    my $control = $self->update_cookie($srch);

    if (!$entry) {  return }
    elsif ($entry->isa("Net::LDAP::Entry")) {
        $self->has_cache and $self->update_cache($entry, $control);
        $self->callback->($srch, $entry, $ref, $control)
            and $self->stop_sync;
    }
    elsif ($entry->isa("Net::LDAP::Intermediate::SyncInfo")) {
        $self->update_cookie($entry);
    }
    else {
        info "UNKNOWN ENTRY [$entry]";
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
    $self->search($srch);
    $srch;
}

sub _search { 
    $_[0]->search
        or croak "[$_[0]] is not currently syncing";
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
