
my @a = split('\\.', $ARGV[1]);
my @b = split('\\.', $ARGV[2]);

sub yield
{
   my $n = shift;
   print "$n\n";
   exit(0);
}

for (;;)
{
   if ($b == 0)
   {
      yield(1);
   }
   if ($a == 0)
   {
      yield(0);
   }

   my $c = shift @a;
   my $d = shift @b;

   if ($b < $a)
   {
      yield(0);
   }
}
