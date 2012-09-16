#
# Copied Makefile for Python documentation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#

# You can set these variables from the command line.
PYTHON       = python
SVNROOT      = http://svn.python.org/projects
SPHINXOPTS   =
PAPER        =
SOURCES      =
DISTVERSION  = $(shell $(PYTHON) tools/sphinxext/patchlevel.py)

ALLSPHINXOPTS = -b $(BUILDER) -d build/doctrees -D latex_paper_size=$(PAPER) \
                $(SPHINXOPTS) . build/$(BUILDER) $(SOURCES)

.PHONY: help checkout update build html htmlhelp clean coverage dist check

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  html      to make standalone HTML files"
	@echo "  htmlhelp  to make HTML files and a HTML help project"
	@echo "  text      to make plain text files"
	@echo "  changes   to make an overview over all changed/added/deprecated items"
	@echo "  linkcheck to check all external links for integrity"
	@echo "  suspicious to check for suspicious markup in output text"

# Note: if you update versions here, do the same in make.bat and README.txt
checkout:
	@if [ ! -d tools/sphinx ]; then \
	  echo "Checking out Sphinx..."; \
	  svn checkout $(SVNROOT)/external/Sphinx-0.6.2/sphinx tools/sphinx; \
	fi
	@if [ ! -d tools/docutils ]; then \
	  echo "Checking out Docutils..."; \
	  svn checkout $(SVNROOT)/external/docutils-0.5/docutils tools/docutils; \
	fi
	@if [ ! -d tools/jinja2 ]; then \
	  echo "Checking out Jinja..."; \
	  svn checkout $(SVNROOT)/external/Jinja-2.1.1/jinja2 tools/jinja2; \
	fi
	@if [ ! -d tools/pygments ]; then \
	  echo "Checking out Pygments..."; \
	  svn checkout $(SVNROOT)/external/Pygments-0.11.1/pygments tools/pygments; \
	fi

update: checkout
	svn update tools/sphinx
	svn update tools/docutils
	svn update tools/jinja2
	svn update tools/pygments

build: checkout
	mkdir -p build/$(BUILDER) build/doctrees
	$(PYTHON) tools/sphinx-build.py $(ALLSPHINXOPTS)
	@echo

html: BUILDER = html
html: build
	@echo "Build finished. The HTML pages are in build/html."

htmlhelp: BUILDER = htmlhelp
htmlhelp: build
	@echo "Build finished; now you can run HTML Help Workshop with the" \
	      "build/htmlhelp/pydoc.hhp project file."

text: BUILDER = text
text: build
	@echo "Build finished; the text files are in build/text."

changes: BUILDER = changes
changes: build
	@echo "The overview file is in build/changes."

suspicious: BUILDER = suspicious
suspicious: build
	@echo "Suspicious check complete; look for any errors in the above output " \
	      "or in build/$(BUILDER)/suspicious.txt"

coverage: BUILDER = coverage
coverage: build
	@echo "Coverage finished; see c.txt and python.txt in build/coverage"

htmlview: html
	 $(PYTHON) -c "import webbrowser; webbrowser.open('build/html/index.html')"

clean:
	-rm -rf build/*
	-rm -rf tools/sphinx

dist:
	-rm -rf dist
	mkdir -p dist

	# archive the HTML
	make html
	cp -pPR build/html dist/python-$(DISTVERSION)-docs-html
	tar -C dist -cf dist/python-$(DISTVERSION)-docs-html.tar python-$(DISTVERSION)-docs-html
	bzip2 -9 -k dist/python-$(DISTVERSION)-docs-html.tar
	(cd dist; zip -q -r -9 python-$(DISTVERSION)-docs-html.zip python-$(DISTVERSION)-docs-html)
	rm -r dist/python-$(DISTVERSION)-docs-html
	rm dist/python-$(DISTVERSION)-docs-html.tar

	# archive the text build
	make text
	cp -pPR build/text dist/python-$(DISTVERSION)-docs-text
	tar -C dist -cf dist/python-$(DISTVERSION)-docs-text.tar python-$(DISTVERSION)-docs-text
	bzip2 -9 -k dist/python-$(DISTVERSION)-docs-text.tar
	(cd dist; zip -q -r -9 python-$(DISTVERSION)-docs-text.zip python-$(DISTVERSION)-docs-text)
	rm -r dist/python-$(DISTVERSION)-docs-text
	rm dist/python-$(DISTVERSION)-docs-text.tar

check:
	$(PYTHON) tools/rstlint.py -i tools
