urlio
=====

Filesystem like access to urls

Getting Started
---------------

Installation

```
pip install git+git@github.com:TraxTechnologies/python-urlio.git#egg=urlio
```

Using urlio
```python
from urlio import Url

url = Url('smb://filex.com/comm/ftp/foo')
for child in url.ls():
    if child.isdir():
	print("Directory {}".format(child))
    else:
	print("File {}".format(child))


url = Url('smb://filex.com/comm/ftp/foo/bar.txt', 'w')
url.makedirs()
url.write('kewl example text')

url = Url('smb://filex.com/comm/ftp/foo/bar.txt', 'r')
assert url.exists()
assert url.read() == 'kewl example text'
```

Issues
------

Issues can be reported to devops@traxtech.com or via the [github issue tracker](https://github.com/TraxTechnologies/python-urlio/issues/new)

Contributing
------------

Check out the code and make a working environment

```
git clone git@github.com:TraxTechnologies/python-urlio.git
virtualenv venv --python=python3
source venve/bin/activate
pip install -r requirements.txt
```

We are using tox and pytest for tests.

```
tox -- -v
```

> TODO: This documentation probably needs updating
