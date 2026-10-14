.PHONY: install test run lint scan clean

install:
	python -m pip install -r requirements.txt
	python -m pip install -e .

test:
	pytest -q

run:
	python -m detection_as_code pipeline

lint:
	python -m detection_as_code lint

scan:
	python -m detection_as_code scan

clean:
	rm -rf reports/ .pytest_cache/ __pycache__/ */__pycache__/ */*/__pycache__/
