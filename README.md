##Trax Common Python Library


### Build Status

####Stable (version 0.5.13)

[![Build Status](https://ci.traxtech.com/buildStatus/icon?job=python-common-prod)](https://ci.traxtech.com/job/python-common-prod/) 

####Development (version 0.5.14~1430119223)

[![Build Status](https://ci.traxtech.com/buildStatus/icon?job=python-common-dev)](https://ci.traxtech.com/job/python-common-dev/)

### Development Setup (OSX Virtualenv)

* Before you begin development on python-common you should set up your [osx development environment for python](http://hackercodex.com/guide/python-development-environment-on-mac-osx/).

* Clone the repository & create a virtual environment.

  ```
  cd Virtualenvs
  git clone git@github.com:TraxTechnologies/python-common.git
  virtualenv python-common
  ```
* Enter the new virtual environment and install the needed depenencies.

  ```
  cd python-common
  source bin/activate
  pip install -r requirements.txt
  ```
  
* There is one dependency (libmagic) that won't be installed via pip. The library for libmagic can be installed with homebrew.

  ```
  brew install libmagic
  ```
  
* You should now have all the dependencies installed. You can run the tests to verify everything is correctly set up.

  ```
  bin/python bin/nosetests -v
  ```
