use Module::Build;

Module::Build->new(
    module_name		=> "Net::LDAPx::Sync",
    license		=> "bsd",
    configure_requires	=> {
	"Module::Build"	    => "0.38",
    },
    build_requires	=> {
	"Test::More"	    => "0.96",
    },
    requires            => {
        "Carp"                      => "0",
        "Data::UUID"                => "0",
        "Moo"                       => "0",
        "MooX::Role::WeakClosure"   => "0",
        "Net::LDAP"                 => "0",
        "Try::Tiny"                 => "0",
    },
    meta_merge		=> {
	resources   => {
	    repository => "http://github.com/mauzo/Net-LDAPx-Sync",
	    bugtracker => "https://rt.cpan.org/Public/Dist/" .
		"Display.html?Name=Net-LDAPx-Sync",
	},
    },
)->create_build_script;
