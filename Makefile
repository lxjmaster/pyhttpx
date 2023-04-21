PYTHON := $(shell command -v python3)

fmt:
	command -v black || $(PYTHON) -m pip install -r requirements.txt
	black pyhttpx

lint:
	command -v pylint || $(PYTHON) -m pip install -r requirements.txt
	pylint pyhttpx
