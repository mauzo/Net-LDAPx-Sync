package Net::LDAPx::Sync;

use Moo;
no warnings "uninitialized";

use Carp;
use Try::Tiny;

use Net::LDAP;
use Net::LDAP::Constant qw[
    LDAP_SUCCESS LDAP_CANCELED
    LDAP_SYNC_REFRESH_ONLY LDAP_SYNC_REFRESH_AND_PERSIST
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

sub _do_callback {
    my ($self, $srch, $entry, $ref) = @_;
    info "CALLBACK [$entry]";
    my $control = $self->update_cookie($srch);

    if (!$entry) {  return }
    elsif ($entry->isa("Net::LDAP::Entry")) {
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
