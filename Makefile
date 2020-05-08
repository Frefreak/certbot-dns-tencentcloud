all: upload

.PHONY: upload

upload:
	rm -rf dist
	python setup.py sdist bdist_wheel
	twine upload --repository pypi dist/*


