# TODO:
## Text
1. General thing that are good to have:
    - Add more structured explanation and details to each description of figure.
    - Write more details to already created bullet points with detailed explanation (coherent writting as flow).
    - Extract more information and details from each reference.
    - Extend ideas and sections also by adding text, algorithms, tables, figures.
    - Edit grammar mistakes in draft and check its coherence by rereading / reviews from others (refine text to be more academically and have rich grammar)
    - Check text for plagiarims and use of AI.
1. Notes from reviewer/supervisor:
    - decompose subchapter "Compromise and trust in security" to 2-3 subchapter because it is too long
    - Analyzer упомянут, но какие именно алгоритмы или модели он использует для вынесения вердиктов, не раскрыто. Можно ли описать, как будут выявляться “критические компоненты” или аномалии: правила, ML-модели, сигнатуры?
    - Нужно обязательно расширить раздел Results экспериментальными данными, либо чётче показать, что методология базируется на проверенных компонентах (напр., использовать существующие песочницы, известные инструменты – это подразумевается, но можно указать примеры типа Cuckoo Sandbox и как они интегрируются).
    - Как говорилось выше, нужны экспериментальные проверки, если это возможно. Можно запустить ограниченный эксперимент: например, запустить прототип (пусть даже вручную) на нескольких зависимостях с известными уязвимостями или бэкдорами и показать, что он собирает определённые поведенческие данные. Даже если без полноценных метрик, описательный пример усилит доверие к выводам.
    - В раздел Conclusion или Discussion нужно вписать что то типа: «в отличие от существующих решений X и Y, наш подход делает Z». Можно вставить небольшой параграф сравнения с конкретными инструментами SCA или исследовательскими работами (как упоминалось, QUT-DV25, SandDriller и т.п.), чтобы рецензенты MDPI (https://www.mdpi.com/journal/computers) увидели понимание ландшафта. Надо сформулировать уникальный вклад статьи (например: «мы первые предложили использовать песочницы для проактивного SCA в DevOps, тогда как предыдущие работы фокусировались либо на статике, либо на пост-фактум анализе инцидентов»).
1. Methodology:
    - алгоритмы, pseudocode, блок-схемы, UML diagrams
    - UML diagrams and logical model with details: refined architecture, component diagram based on architecture, package diagram for project layout, use case scenarios / diagrams (from system perspective), user stories (from user perspective), flowcharts, entity diagram, maybe write some parts within excel tables. Перерисовать или дорисовать UML diagrams: Use Case Diagram (need use case scenarios and more use cases), Sequence Diagram, Class Diagram, Component Diagram, Activity Diagram. Redraw architecture as UML Package Diagram and component diagram
    - Physical model: dependencies and technologies (programming languages, network protocols, etc.). MVP / PoC of the platform (for storing, analysis, analytics of software distributions). It will be practical implementation or prototype that tries to prove hypothesis and theories, consisting of: CLI toolkit, web-ui, desktop-gui, backend-api, etc.
1. Results:
    - Результатом гипотезы (данные графики таблицы).
    - Перерисовать level-0 dfd чтобы там были описаны базовые взаимодействия а не только одна стрелка потоков данных.
    - Перерисовать некоторые потоки данных в level-1 dfd (направления стрелок, где VPN должны быть двунаправленными). Level 1+ dfd тоже перерисовать, ведь они слишком походят на блок-схемы чем на dfd
    - Перерисовать Attack scenarios (attack tree / paths / vectors), чтобы было более детально и понятно и риски.
    - Более детальное сравнение с другими решениями в этой области и исследованиями. Сравнение с другими решениями результаты с альтернативами (другими state-of-the-art SCA) по кол-ву сбора данных (что действительно больше низкоуровневых и качественных данных) на одинаковом датасете (из wheel файлов к примеру). Также сравнить отдельно и совместно с SCA (e.g., OWASP Dependency Check),  что определить насколько много our выстроенный proposal with malware analysis tools (e.g., Cuckoo Sandbox) могут дополнять их.

## Technical debt
1. Move preamble (package imports and configs) to separate file
1. Migrate to bibtex because IEEETran has not fully correct styling for biblatex
1. \usepackage{fancyhdr} for heading
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
1. Адаптировать SIST powerpoint шаблон на beamer (7-10 минут длительность)
1. CLI export from draw.io as script
1. toolkit or someway to generate mindmap from table of concepts in .tex file (https://en.wikipedia.org/wiki/List_of_concept-_and_mind-mapping_software)
1. Deduplication and autoformatting of .bib file (https://tex.stackexchange.com/questions/233086/avoiding-duplicate-entries-in-bibliography-having-different-cite-keys)
1. Загрузить теоретическую статью в SIST (https://sist.astanait.edu.kz/) до 15-го декабря
