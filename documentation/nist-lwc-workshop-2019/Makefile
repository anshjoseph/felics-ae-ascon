all: paper slides

paper slides: %: results/%.pdf

results/%.pdf: %.tex references.bib | results
	latexmk -pdf -interaction=nonstopmode -outdir=results -auxdir=results $<

results:
	mkdir results

clean:
	-rm -r results
