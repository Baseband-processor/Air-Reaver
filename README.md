Air::Reaver
================================================

![image of reaver_bg](./reaver_bg.jpg)


**WHO I AM?**

Read the Github description :)




**REQUIREMENTS**

- [x] perl 
- [x] libpcap
- [x] flex
- [x] C compiler (gcc is fine)

**INSTALLATION**

for installing the *Air::Reaver* and *ReaverWPS* programs you just need to type:

```shell
   sudo make

```

this will start the Makefile outside the C and perl directories, Reaver's Headers will be automatically installed in */usr/include*.
directory.


**C DOCUMENTATION and WPS standard**
 
some resources about C Reaver program and WPS standards are here:
  - _HACKING EXPOSED™ WIRELESS: WIRELESS SECURITY SECRETS & SOLUTIONS SECOND AND THIRD EDITION_ 
  - https://www.ccs.neu.edu/home/noubir/publications-local/SNN13.pdf
  - http://oldwww.dcs.fmph.uniba.sk/bakalarky/obhajene/getfile.php/main.pdf?id=210&fid=412&type=application%2Fpdf
  - https://pdfs.semanticscholar.org/7ab6/c8f5e9f2f6ede77f8da8c4fb1ba4d74103ae.pdf
  - https://core.ac.uk/download/pdf/41532612.pdf
  - [official WPS documentation (2006) ](http://cfile28.uf.tistory.com/attach/16132E3C50FCFFCB3EC74E)

**PERL DOCUMENTATION**

if interested in more advanced examples for the perl library please go under the *examples/* directory.

the most basic usage is:



**SPECIAL THANKS**

A great thanks to *Andreas Hadjiprocopis* (aka *Bliako*), probably the best collaborator I ever had, without him the biggest part related to the C code would be broken.

**other thanks**


*  

**Future works and directions**

This library is the result of 2 months of hard work and, still now, there are several problem related to the perl-types conversion, 
Probably the project will grow even more, my main ideas are:

- [ ] offer a full coverage for the Reaver header files
- [ ] Integrate Air::Reaver with other modules, those are
   * Air::Lorcon2 -> interface to Lorcon2 library
   * Air::Pcap -> interface to airpcap library
   * Air::Crack -> interface to aircrack-ng
   * Air::KRACK -> implementation of the KRACK attack
   * Air::FakeAP -> implementation of Fluxion
   
- [ ] Write a brief PDF manual about the six perl wireless-security module

**Other suggested Perl libraries for network security**

unfortunately perl doesn't have the same number of libraries as python, but some exists!
for starting I suggest to learn:

* [Socket](https://metacpan.org/pod/Socket)
* [Net::Pcap](https://metacpan.org/pod/Net::Pcap)
* [Net::Ncap](https://metacpan.org/pod/Net::Ncap)
* [Net::Frame](https://metacpan.org/pod/Net::Frame)
* [NetPacket](https://metacpan.org/pod/NetPacket)
* [Net::Write](https://metacpan.org/pod/Net::Write)
* [Net::Analysis](https://metacpan.org/pod/Net::Analysis)
* [Net::Silk](https://metacpan.org/pod/Net::Silk)
* [Net::Inspect](https://metacpan.org/pod/Net::Inspect)
* [Net::Tshark](https://metacpan.org/pod/Net::Tshark)
* [Net::Sharktools](https://metacpan.org/pod/Net::Sharktools)
* [File::PCAP](https://metacpan.org/pod/File::PCAP)
* [Net::P0f](https://metacpan.org/pod/Net::P0f)
* [Net::Pcap::Reassemble](https://metacpan.org/pod/Net::Pcap::Reassemble)
* [Nagios::NRPE](https://metacpan.org/pod/Nagios::NRPE)
* [Net::Connection::Sniffer](https://metacpan.org/pod/Net::Connection::Sniffer)
* [Net::ARP](https://metacpan.org/pod/Net::ARP)

**PERL NETWORK SECURITY RESOURCE**

* _Automating System Administration with Perl_ (Probably one of the best books for the blue team field practices in Perl)
* _Network Programming With Perl (by Lincoln Stein, 2001)_ (even if old, still remains the best networking book for Perl developers)
* [Practical PERL for Security Practitioners](https://www.sans.org/reading-room/whitepapers/scripting/practical-perl-security-practitioners-1357)
* [Perl for Penetration Testing](https://www.slideshare.net/kost/perl-usage-in-security-and-penetration-testing)


**Requests and collaborations**

Feel free to email me at <Baseband@cpan.org>
- [x] I am open to suggestions, code improvement, collaboration and other requests


**PAID SERVICES**

if you want to have a customized implementation of your favorite wireless-hardware you can write me at EdoardoMantovani@Lorcon2.com and we can agree about the price of the service.

More info here: https://github.com/Baseband-processor/Perl-awk-services/blob/master/README.md


**CURRENT VERSION**

After a long development stage, the actual version of Air::Reaver is 17.7, for more about the enhancement of various functions see the _Change_ file inside the Perl directory.


**COPYRIGHT AND LICENCE**

Copyright (C) 2020 by *Edoardo Mantovani*, aka BASEBAND


This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


<img src="https://media3.giphy.com/media/ADiOs8AqeverrAuT4Q/giphy.gif" alt="drawing" width="2000"/>
