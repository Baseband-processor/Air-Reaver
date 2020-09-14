sub BEGIN{
   `tar -xvf C.tar.gz`;
}

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME => 'Air::Reaver',
   LICENSE => 'perl',
   AUTHOR => 'Edoardo Mantovani aka Baseband',
   DEFINE => '',
   VERSION_FROM => 'lib/Air/Reaver.pm',
   LIBS => ['-L/lib -L/usr/lib -L/usr/local/lib -LC/src'],
   INC => '-I/include -I/usr/include -I/usr/local/include -IC/src',
   MIN_PERL_VERSION => '5.22.1',
   PREREQ_PM => {
  },
);