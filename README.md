## python-beid - BEID helpers for Python

Those helpers are meant to be used on a RaspberryPi with Raspbian Jessie (tested on B+ and 2), but it should work fine on other platforms/OS, with perhaps some adjustments for the prerequisites.

###Prerequesite :

Basicaly, the helpers only need pyscard, and the drivers for the reader (libacr38u for the "official" Beid readers).

Btw, for pyscard to install and work correctly with Python 3 (at least in Raspbian Jessie), one should compile and install it from git sources :

    sudo apt-get install swig libpcsclite-dev libacr38u python3-setuptools build-essential git
    git clone https://github.com/LudovicRousseau/pyscard.git
    cd pyscard
    python3 setup build_ext install
    cd ..
    rm -fr pyscard

###Installation

    git clone https://github.com/Lapin-Blanc/pythonbeid.git
    cd pythonbeid
    python3

###Utilisation :

    from beid import BeidReader
    from pprint import pprint

    class MyReader(BeidReader):
        def on_inserted(self, card):
            pprint(card.read_infos())

    my_reader = MyReader()

    print(my_reader.card.num_carte)
    print(my_reader.card.num_nat)
