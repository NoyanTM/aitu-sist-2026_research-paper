# practice

## Description
Discrete event simulation with agent based modeling to represent a software supply chain with quality gates and without in order to compare how they can affect on the security posture of the ecosystem (e.g., PyPI and Python). 

Such simulation is only a abstract model that tries to represent reality in limited form and consists of environment, rules, entities, interactions/behaviors/actions, time (tickrate / continous time space with steps in time-based or event-based simulations), etc. There are multiple types of forms of simulations implementations for different domains and task. They are applied for predictive analysis of cases and situations that are hard to test in real world or more cost-effective to do. However, such simulations tend to drift and desynchronize (rapidly diverging from reality), so they should be continuously updated or recalibrated to remain aligned with real-world conditions. For example, a major event might occur that shifts the entire landscape in reality, but our simulation fails to reflect it because it is restricted by predefined boundaries / too static.

## Requirements
- Machine for testing: Debian 13 GNU/Linux x86_64
- Python interpreter version: CPython 3.13.5
- Setup commands:
```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
- Configurations for experiments are loaded from config.json file.
- Run experiments:
```sh
python3 model.py > ./data/results.txt
jupyter notebook # @TODO: move some scripts from model.py to analysis.ipynb
```

## Future work and major enhancements
Firsly, we initially used [Mesa](https://github.com/mesa/mesa/) framework for Python. However, it contains too many abstraction layers and components (e.g., grids, hexagons, etc.) that are unmanageable. Therefore, we are going to migrate to a reasonable stack of libraries like simpy and heapq/queue to combine with sqlite, numpy, matplotlib, gevent/asyncio, networkx, and concurrent/parallel execution (processes and threads for concurrent agent-based simulations). 

Secondly, we will try to create our own game (or game/simulation engine) like PlagueInc with GameDevTycoon in golang/c with raylib (or web js-based), but from perspective of attackers vs. defenders on software supply chain in PyPI (and other repositories or distributions) for gamification.

Thirdly, we consider creating an experiment with actor model (attackers vs. defenders) by using generative language models (local SLM especially) to represent users more accurately and dynamically (each of them with their own unique background and context affecting on actions + social interactions like chatting within discussion groups to express their opinions or news / reports) on self-hosted environment within multiple virtual machines (with services like gitea, prometheus, and so on), rather than using random number generator with simple simulation.

## Optional features and technical debt
1. Actor can become INACTIVE. For example, developer can get out of certain ecosystem or comeback. Moreover, package publisher can lost his account, abandon account with their software, transfer control to other, and so on.
1. Currently, 1 step represents 1 working days that contains 1 action per actor. Probably, we should not be restricted by one-to-one match by instead representing 1 days in 24 hours in 24 steps of actions. Can we try to match real seconds in compressed time? And how to properly measure ranges of time, because we have 365 days that is range from 0 to 364 (changing initial time or including/excluding ranges)? Also, possible to change action in day like developer started to do action but couldn't complete "remove_packages" but not local_packages, so he wasted only half of this step and started to do other action instead.
1. Represent structured workflow of actors rather than random set of actions. For example, developer has its own SDLC for specific project with working schedule, plan of prepared actions (planning, searching, coding, creating pull request, doing nothing, etc.), being interupted by manager or other situations (e.g., talking about requirements). However, it should depend on their types, categories, and groups (e.g., backend engineer's behavior and responsibilities differs from frontend one).
1. @TRANSLATE(ENGLISH): Introduce boostrapping для подготовки с рандомными пакетами и предзаданными состояниями данных от которым будет двигаться симуляция дальше, ведь если заранее не будет boostrap подготовки то акторы по типу developers будут просто проистаивать или скипать шаги ведь не будет пакетов для скачивания. Also, gradual amount changes (increases or decreses) of actors более натурально что экосистема будет наполнятся акторами постепенно ведь они постепенно узнают о ней. For example, steamdb показывает волновой эффект, что в определенные промежутки времени активность повышенная и понижается (в нашем случае утром работают, а вечером отдыхают) - хакеры стремятся как раз атаковать в выходные дни чтобы застать системы неготовыми как было с атаками на Ubisoft в Xmas. Более того, тогда нужно отображать GIS данные с картографическим отображением по территории и часовыми поясами.
1. Add "resource" field for repository as simpy.Resource(env, capacity=config["repo_capacity"]) to represent that repository can handle limited amount of users (e.g., 10k concurrent users and more), so someone needs to wait / spend time waitng to resource release. For example, we need to organize it in simple way for multiple actions (just using function def developer instead?) with example from https://gitlab.com/team-simpy/simpy/-/work_items/93:
```python
def run():
    function_call = getattr(...)
    if inspect.isgeneratorfunction(function_call):
        # only for self.install_package,
        # because it creates request to repo
        yield self.env.process(function_call())
    else:
        function_call()

def install_package(self):
    with self.repo["resource"].request() as req:
        yield req
    # also represent network latency, bnadwith, bottlenecks
    # for requests and downloading files with large sizes
    # or it is too much details that should not be simulated
    # but checked in real environment and regular setups
```
1. Recording changed states of environment with actions and results at each step within SQLite database.
1. Probably, need faker or custom dictionaries for randomized metadata (e.g., /usr/share/dict/words or something else).
1. Some enums like DeverloperState are not applied completely, so need to reconsider them or expand.
1. Management of versions in Developer.change_package() and Publisher.update_package() should depend on developer policy, customizable probabilities, and other package requirements. It requires implementing semver parser on BNF according to https://semver.org/. Also, we should check also date of publishing (i.e., env.now), because version specifiers depend on versioning policy of the package.
1. Output data in structured format for analysis and render in different graphical representations.
1. Feature toggles in functions via string keys (not integers) - for example model_reactive, model_preventive, model_combined, etc.
1. Reread comments from codebase and other sources to extract all possible enhancements and features.
1. Add more detailed customization via config.json - for example reducign rate of publisher (publish only 2-3 time a week, not everyday) and more.

## Model of computer simulation
This description contains non-formal description of the model, meaning it is not formal specification like ODD+D format. Our goal is to analyze how quality gates and strict restrictive measures/policies might reduce propagation speed of malwares (i.e., compromised packages), vulnerabilities, and supply chain attacks by simulating a complex dynamic system at multiple levels (from micro to macro). In real environment, we expect that scanners or any preventive approaches (both dynamic and static) are not absolute, because there can be some oversight, so they should be combined with reactive approaches as well.

### Assumptions and specifics with oversimplifications:
- Totally closed system within a single ecosystem (packages from single repository without mirrors). Moreover, the platform with packages itself cannot be compromised in our scenario.
- Stochasticity with probability of event to happen or distribution to have. In our case, it is pseudo-random generator provided by random package in stdlib of Python (i.e., /dev/urandom and /dev/random in Linux).
- Not represented confrontations between different actors (e.g., between threat actors).
- Not represented network issues and latency (e.g,, for package upload or download).
- Limited amount of packages and agents that are way less than in reality.
- Agents have restricted pre-defined roles, but in reality they can shift between / act on multiple roles at same time. For example, package publisher can do same things as regular user. Moreover, some developers and package publishers can be malicious like regular threat actors, but we assume that they have passively good intensions or behavior with the good will.
- Developer or regular user has only single running project at same time, so each dependencies are groupped together and not seperated by projects.
- Not represented that actors can operate in organized groups or specific teams, collaborating toward same goals and projects. For example, developers within data science departments/teams would use numpy or related libraries. Moreover, certain companies or organizations have specific regulations, policies, and a tendency toward certain dependencies based on their internal preferences or domain-specific needs.
- Not represented automatic pipelines with CI/CD and scripts (e.g., test builds that pull packages from repositories to build some artifact) - only represented manual manipulations via package manager toolkit by person.
- Only represented direct dependencies without supply chain attack through transitive dependencies which requires dependency resolution implementation.

### Agents (i.e., entities, actors, objects, structures) with their states and behavior at each steps (i.e., days)
1. Developer or regular user:
    - Install (download and freeze) package from repository with specific version specifier at some regular rate (n packages per t time).
    - Manage already installed packages (drop from project list, change version to newer or older) with regular rate (e.g., once per week).
    - Report about package from repository (e.g., package that you already used but dropped, after found to be compromised by some variation of package, or random package just reported because you want to).
    - Can be compromised, reabilitated, and out of ecosystem.
    - Check yourself and state for possible compromisation. For example, installed compromised package or changed version to compromised one, then you are infected/compromised but you don't know it immediately - it only reveals after 7 days. You have to regulary check (tries randomly from 1 to 7 days) for self-compromisation state, then try to reabilitate in order to be immune/clear/decompromised with 50% chance every 1 to 3 days if found revealed self-compromisation state (need debug information like compromised_by: someone for analysis).
2. Package distributor or publisher:
    - Creates new seperate package for package repository/registry if possible (e.g., some limit of 10 per publisher).
    - Changes package by creating new revision/version or edits previous ones from respository.
    - Can be compromised, reabilitated, and out of ecosystem.
3. Threat actor:
    - Tries to compromise package publisher (e.g., via phishing) in order to compromise dependencies or create supply chain attack
4. Quality gate:
    - Model 1 (reactive without filters and open to anyone). Responsibilities on users to regulate and how to protect against compromisation, because no regulation from platform. But users can report about malware as a reactive measure.
    - Model 2 (combining reactive and preventive with restrictions). Firstly, platform protects its users by introducing quality gates which temporary blocks packages due to multiple factors (states of packages/dependencies: under_consideration, public, blocked, reported, etc.). Secondly, each actor and package has their trust levels (e.g., developer trust specific packages and package publisher for N amount of percentage and it dynamically changes depending on compromisation cases) that are implicit (internal opinion of certain actor) and explicit (given by platform or community scores).
