<h1> Project Kamarketplace </h1>

The aim of this project is to provide a database containing the price timeseries of each resource available in-game. 
Prices will be scraped and then inserted in a PostGreSQL database. Later on, an API will be set-up so anyone can automatically pull the historical prices.

In case you'd like to run the code, please find below the requirements. 

<h1> Prerequisite </h1>

The source code of the game needs to be available. Follow the next instructions to do so.

<h2> How to install FFDEC </h2>

Follow the instructions on this page:
https://github.com/jindrapetrik/jpexs-decompiler/wiki/Installation

The releases are available here
https://github.com/jindrapetrik/jpexs-decompiler/releases

<h2> How to install Dofus (via the Ankama Launcher) </h2>

The Ankama launcher can be installed here:
https://www.ankama.com/fr/launcher

Once the game and FFDEC are installed, you can run **decompile.sh** to extract the source code of the game.

<h2> How to run the code (update March 2023) </h2>
At the being time, the packet deserialization can be run with the python file network.py. 
