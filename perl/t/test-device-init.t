use Test;
BEGIN { plan tests => 5 };

use Net::Interface;
use Air::Crack qw(:aircrack);

foreach( Net::Interface->interfaces() ){
  if( isAirpcapDevice($_) == -1 || isAirpcapDevice($_) != 0){
    return -1;
  }else{
    ok(1); 
  }
