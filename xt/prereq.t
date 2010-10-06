use Test::More;
eval "use Test::Prereq::Build";
plan skip_all => "Test::Prereq::Build required to test dependencies" if $@;
plan skip_all => "Author test.  Set \$ENV{TEST_AUTHOR} to a true value to run" unless $ENV{TEST_AUTHOR};
prereq_ok();
