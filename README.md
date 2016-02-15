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

    from pythonbeid.beid import scan_readers, read_infos, triggered_decorator
    from pprint import pprint
    from time import sleep

    # retrieve a list of available readers
    r = scan_readers()[0]

    # declare a function that will be executed automatically when a card is removed/insterted
    # funcion arguments should be :
    # - action : which will be "inserted" or "removed" when the function will be called
    # - card : which will be the card if inserted
    # - reader : which will hold  the name of the reader to use 

    @triggered_decorator
    def basic_read(action, card, reader=r.name):
        if action=="inserted":
            i = read_infos(card)
            pprint(i)
    
    sleep(5)

    infos = read_infos(r, read_photo=True)
    with open("photo.jpg", "wb") as f:
        f.write(infos['photo'])

