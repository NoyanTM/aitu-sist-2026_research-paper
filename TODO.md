# TODO:
## Technical debt
1. Ensure basic security measures against any potential malware (e.g., \write18 and other vectors in CTAN/TUG packages, templates, etc.) in tex ecosystem:
    - Running latex only within disposable and isolated containers (e.g., --rm option, limiting external internet connection by mapping to localhost, alpine-based images, ...)
    - Proper command line options (e.g., --safer, --no-shell-escape, etc.) and configuration files (i.e., texmf.cnf)
    - Regular updates and management of dependencies
        - Compile from source code and scan/check it regularly (https://github.com/TeX-Live/texlive-source)
        - Do not use untrusted templates/documents/scripts
        - Limit amount as small set of tex packages (do not use large tex-live-full, use tlmgr to download only specific packages)
    - Further, migrate from docker containers to vagrant virtualization to have more isolated environment
    - Secure by design alternative to tex with limited functionality and better implementation? (typst?)
    - References:
        - https://miktex.org/howto/miktex-docker
        - https://www.texdev.net/2010/04/25/tex-and-security/
        - https://stackoverflow.com/questions/2541616/how-to-escape-strip-special-characters-in-the-latex-document
        - http://johnbokma.com/blog/2021/06/18/running-pdflatex-using-alpine-pandoc-latex-image.html
        - https://www.usenix.org/system/files/login/articles/73506-checkoway.pdf
        - https://arxiv.org/pdf/2102.00856
        - https://www.tug.org/TUGboat/tb31-2/tb98doob.pdf
        - https://tug.org/texlive/doc/texlive-en/texlive-en.html#x1-780009.1.6
        - https://tex.stackexchange.com/questions/528262/are-there-any-dangerous-commands-in-latex
        - https://tex.stackexchange.com/questions/10418/how-can-i-safely-compile-other-peoples-latex-documents
        - https://www.maxchernoff.ca/p/luatex-vulnerabilities
        - https://tex.stackexchange.com/questions/100932/is-luatex-as-secure-as-pdftex
        - https://tex.stackexchange.com/questions/107017/why-does-tex-live-require-yearly-updates
        - https://www.tug.org/texlive/doc/texlive-en/texlive-en.html#x1-60001.4
        - https://github.com/overleaf/overleaf
        - https://github.com/overleaf/toolkit
        - https://code.visualstudio.com/docs/devcontainers/containers
1. Utilities: latexxmk (https://github.com/cgraumann/LatexUtils), luatex (https://tex.stackexchange.com/questions/377613/solve-unicode-char-is-not-set-up-for-use-with-latex-without-special-handling-o), formatter and linter (https://github.com/cmhughes/latexindent.pl), spellchecker and grammatical analysis in form of CI/CD (e.g., https://github.com/yegor256/latex-best-practices, gnu aspell, llm, etc.)
1. Publish .pdf as github releases (for initial draft, опубликованная версия, и редактированнные в последствии)
1. На основе этих наработок сделать generic latex template for research paper and other things.
1. Также добавить beamer шаблон (presentation.tex)
1. CLI export from draw.io as script
1. toolkit or someway to generate mindmap from table of concepts in .tex file (https://en.wikipedia.org/wiki/List_of_concept-_and_mind-mapping_software)

