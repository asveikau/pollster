use strict;

my @a = split('\\.', $ARGV[0]);
my @b = split('\\.', $ARGV[1]);

sub yield
{
   my $n = shift;
   print "$n\n";
   exit(0);
}

for (;;)
{
   if (scalar(@b) == 0)
   {
      yield(1);
   }
   if (scalar(@a) == 0)
   {
      yield(0);
   }

   my $c = shift @a;
   my $d = shift @b;

   if ($c < $d)
   {
      yield(0);
   }
}
