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
    meta_merge		=> {
	resources   => {
	    repository => "http://github.com/mauzo/Net-LDAPx-Sync",
	    bugtracker => "https://rt.cpan.org/Public/Dist/" .
		"Display.html?Name=Net-LDAPx-Sync",
	},
    },
)->create_build_script;
