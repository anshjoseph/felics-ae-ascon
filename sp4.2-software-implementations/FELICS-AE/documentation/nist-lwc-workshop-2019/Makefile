all: felics-ae.pdf

%.pdf: %.tex references.bib
	latexmk -pdf -interaction=nonstopmode $<
