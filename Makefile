all: upload

.PHONY: upload

upload:
	rm -rf dist
	python -m build
	twine upload --repository pypi dist/*.whl


