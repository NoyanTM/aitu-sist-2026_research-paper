.PHONY: build

# java -jar plantuml.jar -i ./diagrams/ -o ../build
build:
	pdflatex --output-directory=build paper.tex
	biber ./build/paper
	pdflatex --output-directory=build paper.tex
	pdflatex --output-directory=build paper.tex

# clean: to remove aux
