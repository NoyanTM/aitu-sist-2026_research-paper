import enum
import json
import pathlib
import random
import typing
import copy
import textwrap
import datetime

import simpy
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.lines import Line2D
import networkx as nx


# @AI_GENERATED_EXPERIMENTAL
class SimulationLogger:
    def __init__(self, env, repo, developers, threat_actors):
        self.env = env
        self.repo = repo
        self.developers = developers
        self.threat_actors = threat_actors
        self.step_history = [] 
        self.attack_edges = []
        # Add these to store the final snapshot for the node composition analysis
        self.current_clear_packages = []
        self.current_compromised_packages = []
        self.current_clear_developers = []
        self.current_compromised_developers = []

    def finalize(self):
        """Call this after env.run() to capture the final state of the system."""
        # Categorize Packages
        for p in self.repo["packages"]:
            for v in p["versions"]:
                pkg_label = f"{p['name']}@{v['specifier']}"
                if v["meta_state"] == PackageState.CLEAR:
                    self.current_clear_packages.append(pkg_label)
                else:
                    self.current_compromised_packages.append(pkg_label)
        
        # Categorize Developers
        for d in self.developers:
            dev_label = f"Dev_{d.id}"
            if d.state == DeveloperState.CLEAR:
                self.current_clear_developers.append(dev_label)
            else:
                self.current_compromised_developers.append(dev_label)

    def run(self):
        while True:
            all_versions = [v for p in self.repo["packages"] for v in p["versions"]]
            total_compromised = sum(1 for v in all_versions if v["meta_state"] == PackageState.COMPROMISED)
            total_clear = sum(1 for v in all_versions if v["meta_state"] == PackageState.CLEAR)
            dev_compromised = sum(1 for d in self.developers if d.state == DeveloperState.COMPROMISED)
            
            self.step_history.append({
                "step": int(self.env.now), # Ensure this is an int
                "compromised_packages": total_compromised,
                "clear_packages": total_clear,
                "compromised_developers": dev_compromised
            })

            for p in self.repo["packages"]:
                for v in p["versions"]:
                    if v["meta_state"] == PackageState.COMPROMISED:
                        edge = {
                            "threat_actor": v["meta_compromised_by"],
                            "package": f"{p['name']}@{v['specifier']}"
                        }
                        if edge not in self.attack_edges:
                            self.attack_edges.append(edge)

            yield self.env.timeout(1)


class PublisherState(enum.StrEnum):
    CLEAR = enum.auto()
    COMPROMISED = enum.auto()


class PackageState(enum.StrEnum):
    CLEAR = enum.auto()
    COMPROMISED = enum.auto()


class DeveloperState(enum.StrEnum):
    CLEAR = enum.auto() # healthy and remediated
    COMPROMISED = enum.auto() # infected device or system but still active
    # PROTECTED = enum.auto() # protected against specific compromised package


class Version(typing.TypedDict):
    """Version of package/dependency with additional metadata"""
    specifier: str
    meta_compromised_by: int # id of threat_actor, but later need name to represent APT groups
    meta_state: PackageState # statuses like clear, compromised, blocked, etc.
    # @TODO: meta_compromisation_type


class Package(typing.TypedDict):
    name: str # acts as unique key and cannot be duplicates by name
    description: str
    owner: id
    versions: list[Version] # variations and releases with at least one version


class Repository(typing.TypedDict):
    packages: list[Package]
    # @TODO: state: online, offline, compromised,
    # under dos/ddos attack, and other debug metadata


def _generate_package(n: int, owner_id: int, versions: int) -> Package | list[Package]:
    packages = []
    for i in range(n):
        random_package_id = [f"{random.randint(0, 9)}" for i in range(32)]
        random_package_id = "".join(random_package_id)
        package = {
            "name": f"random-name-{random_package_id}",
            "description": "random-blank-description",
            "owner": owner_id,
        }

        # generate unique set of possible versions and limited
        # by major_version == 9, but later it should generate
        # ranges from 0.0.1 to 9.9.9 or according to semver
        possible_versions = [f"{i}.0.0" for i in range(1, 9 + 1)]
        specifiers: list[str] = random.sample(possible_versions, k=versions)
        generated_versions = []
        for specifier in specifiers:
            version: Version = {
                "specifier": specifier,
                "meta_compromised_by": 0,
                "meta_state": PackageState.CLEAR,
            }
            generated_versions.append(version)
        package["versions"] = generated_versions
        packages.append(package)

        if n == 1:
            packages = packages[0]
            break
    return packages


class Developer:
    """
    Represents regular user or developer that uses 
    PyPI or any other package distribution platform
    in order to obtain third-party dependencies and tools
    for a single project that they are working in
    """

    def __init__(self, env: simpy.Environment, id: int, actions: dict, repo: dict, model: int, state: DeveloperState = DeveloperState.CLEAR):
        self.env = env
        self.id = id
        self.actions = actions
        self.state = state
        self.repo = repo
        self.model = model
        self._local_packages: list[dict] = list()
        self._protected_against: list[dict] = list()
        self._compromised_by: list[dict] = list()

        self.action = env.process(self.run())

    def run(self):
        while True:
            current_action = random.choices(population=list(self.actions.keys()), weights=self.actions.values(), k=1)[0]
            print(textwrap.dedent(f"""
                --------------------------------------------------------------
                developer: id:{self.id}
                state:{self.state}
                step:{self.env.now}
                action:{current_action}
                local_packages:{self._local_packages}
                protected_againts:{self._protected_against}
                compromised_by:{self._compromised_by}
                --------------------------------------------------------------
            """))
            function_call = getattr(self, current_action)
            function_call()
            yield self.env.timeout(1)

    def check_state(self):
        """
        Checks current state to apply set of actions on instance. For example,
        developer changes its state to Developer.COMPROMISED when installs/updates to
        compromised dependency version.
        
        It depends on proper package handling in self.install_package and self.change_package
        that automatically add compromised version of packages to self._compromised_by and check for
        self._protected_againts in order to not being compromised by same packages multiple times
        (i.e., cases when removed/installed/changed compromised packages and then added them again
        which is basically being compromised by same package multiple times).
        
        For now, threat actor can only compromise packages by acting on behalf of publisher without
        any other way of direct hacking to endpoints (e.g., compromising older versions, republishing
        copy of same package, and other complex tactics/strategies). Also, we should implement 
        complex protective measures for model == 2 such as trust factors of packages/publishers, 
        against specific form (categories) of malware or threat by using specific software or tools
        (more granular but not against everything).
        """
        # no stacks of compromisation due to packages with clear state 
        if self.state is DeveloperState.CLEAR and not self._compromised_by:
            return
        
        # get first of compromisations, ideally it should get from latest ones
        # because they are more popular or even pulls one of random package by looping with retries
        # that was added after 7-14 days (or search for it) for imitating compromisation reveal
        oldest_compromised = self._compromised_by[0]
        
        if not any(self.env.now - oldest_compromised["time"] > i for i in range(7, 14)):
            return

        # action to decompromise/remediation with 50/50 chance due to technical issues
        # (e.g., leaks of credentials require to change all keys and passwords,
        # creating specific rules for malware pattern detection like yara rules, 
        # trojan or hidden C2 control require to cleanup all devices, and so on)
        is_decompromised_success = random.randint(0, 1)
        if not is_decompromised_success:
            return
        self._report_package(random=False, package=oldest_compromised["package"])
        self._compromised_by.pop(0)

        # change state to CLEAR as applying decompromisation effect
        # if only stacks of previous compromisation effects are empty
        # (i.e., mechanics like negative effects in adventure games)
        if not self._compromised_by:
            self.state = DeveloperState.CLEAR

    def install_package(self):
        """
        Tries to install available variation of package
        from the repository by imitating search using randomness
        """
        if not self.repo["packages"]:
            return
        
        found_package = random.choice(self.repo["packages"])
        
        # skip duplicates by their name, because of temporary limitation that
        # we have single local package variation in a single project per developer
        if any(found_package["name"] == package["name"] for package in self._local_packages):
            return

        # storing local_package with only exact pinned version instead of all package variations,
        # using copy.deepcopy() instead of dict.copy() to handle when Package will have nested structure
        pinned_version: Version = random.choice(found_package["versions"])
        local_package = copy.deepcopy(found_package)
        local_package.pop("versions", None)
        local_package["version"] = pinned_version
        
        # protection against specific package variations
        for protected in self._protected_against:
            if (local_package["name"] == protected["name"] and
                local_package["version"]["specifier"] == protected["version"]["specifier"]):
                return
        
        # being compromised by zero day or security scanner missed
        # but checking if already compromised by same package and 
        # do not add again it to prevent unnecessary duplicates
        already_in_compromised_by = any(
            local_package["name"] == compromised["package"]["name"] and
            local_package["version"]["specifier"] == compromised["package"]["version"]["specifier"]
            for compromised in self._compromised_by
        )
        if not already_in_compromised_by and local_package["version"]["meta_state"] is PackageState.COMPROMISED:
            self.state = DeveloperState.COMPROMISED
            self._compromised_by.append({
                "package": local_package,
                "time": self.env.now,
            })
        
        self._local_packages.append(local_package)

    def change_package(self):
        """
        Changes version of attached/used package to other one
        (e.g., newer or older) from the repository if available
        """
        if not self._local_packages:
            return

        # searching for the same package in the repository with 
        # an assumption that packages are not being removed from it
        local_package = random.choice(self._local_packages)
        found_package = None
        for package in self.repo["packages"]:
            if package["name"] == local_package["name"]:
                found_package = package
        
        # no other version available for such package
        if (len(found_package["versions"]) == 1 and
            found_package["versions"][0] == local_package["version"]):
            return

        # randomly choosing version from available ones by looking only at major version specifier
        # and we expect correctly formatted version that is restricted by our rules
        major_versions: list[int] = [int(version["specifier"].split(".")[0]) for version in found_package["versions"]]
        latest_major_version: int = max(major_versions)
        local_major_version: int = int(local_package["version"]["specifier"].split(".")[0])
        found_version = None
        if latest_major_version > local_major_version:
            # constant tendency towards migration to latest available version
            # 1.0.0 and 2.0.0 (current) and 3.0.0 -> 3.0.0 (100%)
            # 1.0.0 and 2.0.0 (current) and 3.0.0 and 4.0.0 -> 4.0.0 (100%)
            found_version = f"{latest_major_version}.0.0"
        else:
            # our version is already latest, so 30% distributed amount smaller
            # ones to downgrade and 70% to remain on same version
            # 1.0.0 and 2.0.0 (current) -> 2.0.0 (70%) and 1.0.0 (30%)
            num_smaller = len(major_versions) - 1
            weights = [70] + [30 / num_smaller] * num_smaller
            found_version = random.choices(sorted(major_versions, reverse=True), weights=weights, k=1)[0]
            found_version = f"{found_version}.0.0"

        # protection against specific package variations
        for protected in self._protected_against:
            if (found_package["name"] == protected["name"] and
                found_version == protected["version"]["specifier"]):
                return
        
        # change package version to other with metadata
        for version in found_package["versions"]:
            if version["specifier"] == found_version:
                local_package["version"] = version
                break
        
        # being compromised by zero day or security scanner missed
        # but checking if already compromised by same package and 
        # do not add again it to prevent unnecessary duplicates
        already_in_compromised_by = any(
            local_package["name"] == compromised["package"]["name"] and
            local_package["version"]["specifier"] == compromised["package"]["version"]["specifier"]
            for compromised in self._compromised_by
        )
        if not already_in_compromised_by and local_package["version"]["meta_state"] is PackageState.COMPROMISED:
            self.state = DeveloperState.COMPROMISED
            self._compromised_by.append({
                "package": local_package,
                "time": self.env.now,
            })

    def remove_package(self):
        """
        Removes certain package from locally installed
        because no longer uses it or due to other conditions
        """
        if not self._local_packages:
            return
        self._local_packages.remove(random.choice(self._local_packages))

    def _report_package(self, random: bool, package: dict):
        """
        Tries to report about certain package as compromised or malware
        to be blocked with a reactive approach from repository administration
        """
        # Ideally, it should report random packages from local_packages,
        # packages that you previously used but removed, or packages to be
        # found compromised after 1 to 7 days/steps (check_state), but now it reports
        # just random packages from available in local_packages and removes it. 
        # Also, report of package should be sended to repository administrator
        # or publisher and then validated againts possible compromisation and issues.
        if not self._local_packages:
            return

        # add package as blocked one and remove locally
        # if it is still stored in our local packages
        # even if we uninstalled it previosly, meaning we are still 
        # compromised by single occurance installation/execution
        if random:
            package = random.choice(self._local_packages)

        # with assumption that protected_against does not
        # contain duplicates because install_package and change_package
        # properly checks for protected to prevent being compromised
        self._protected_against.append(package)

        if package in self._local_packages:
            self._local_packages.remove(package)


class Publisher:
    """
    Represents publisher of packages, source code, and other
    software products/projects distributions forms. He can be
    compromised by ThreatActor for some period of time
    (now only for a single package and not long periods)
    to act on his behalf / being controlled by in order to 
    publish compromised packages. Therefore, we probably
    need similar method from Developer.check_state()
    to handle decompromisation activities.
    """

    def __init__(self, env: simpy.Environment, id: int, actions: dict, repo: dict, model: int, state: PublisherState = PublisherState.CLEAR):
        self.env = env
        self.id = id
        self.actions = actions
        self.state = state
        self.repo = repo
        self.model = model

        self.action = env.process(self.run())

    def run(self):
        while True:
            current_action = random.choices(population=list(self.actions.keys()), weights=self.actions.values(), k=1)[0]
            print(textwrap.dedent(f"""
                --------------------------------------------------------------
                publisher: id:{self.id}
                state:{self.state}
                step:{self.env.now}
                action:{current_action}
                published_packages:{[package for package in self.repo["packages"] if package["owner"] == self.id]}
                --------------------------------------------------------------
            """))
            function_call = getattr(self, current_action)
            function_call()
            yield self.env.timeout(1)

    def publish_package(self):
        owned_packages = [package for package in self.repo["packages"] if package["owner"] == self.id]
        
        is_limited_by_max_packages_per_publisher = len(owned_packages) >= self.repo["properties"]["max_packages_per_publisher"]
        is_limited_by_max_packages = len(self.repo["packages"]) >= self.repo["properties"]["max_packages"]
        if is_limited_by_max_packages or is_limited_by_max_packages_per_publisher:
            return
        
        # comparing to available packages in repository, because new package requires unique name
        while True: # @TODO: probably need limit of attempts to prevent long loops
            new_package: Package = _generate_package(n=1, owner_id=self.id, versions=1)
            if all([new_package["name"] != package["name"] for package in self.repo["packages"]]):
                break
        
        self.repo["packages"].append(new_package)
    
    def update_package(self):
        owned_packages = [package for package in self.repo["packages"] if package["owner"] == self.id]
        
        if not owned_packages:
            return
        
        package = random.choice(owned_packages)

        if len(package["versions"]) >= self.repo["properties"]["max_package_versions"]:
            return
        
        # temporary limitation of 9 versions per package
        if len(package["versions"]) >= 9:
            return

        # create new latest version to corresponding package
        latest_major_version: int = max([int(version["specifier"].split(".")[0]) for version in package["versions"]])
        new_major_latest_version = latest_major_version + 1
        if new_major_latest_version > 9: # temporary limitation of 9 versions per package
            return
        new_version: Version = {
            "specifier": f"{new_major_latest_version}.0.0",
            "meta_compromised_by": 0,
            "meta_state": PackageState.CLEAR
        }
        package["versions"].append(new_version)


class ThreatActor:
    def __init__(self, env: simpy.Environment, id: int, repo: dict, meta_config: dict):
        self.env = env
        self.id = id
        self.repo = repo
        self.meta_config = meta_config # @TODO: temporary workaround to know about all package_publishers, instead repo should store about them
        self._publishers: list[int] = [i for i in range(1, self.meta_config["num_publishers"] + 1)]
        # self._compromised_artifacts = list()
        self._counter = 0 

        self.action = env.process(self.run())

    def run(self):
        while True:
            compromised_artifacts = []
            for package in self.repo["packages"]:
                for version in package["versions"]:
                    if (version["meta_state"] is PackageState.COMPROMISED and
                        version["meta_compromised_by"] == self.id):
                        compromised_artifacts.append(
                            (package["name"], version["specifier"])
                        )
            current_action = "preparing_attack" if self._counter < 14 else "executing_attack"
            print(textwrap.dedent(f"""
                --------------------------------------------------------------
                threat_actor: id:{self.id}
                step:{self.env.now}
                action:{current_action}
                compromised_artifacts:{compromised_artifacts}
                --------------------------------------------------------------
            """))

            # tries to compromise random publisher (e.g., via phishing) in order to 
            # create supply chain attack by publishing multiple new versions of packages
            # or new packages with compromised state at rate of every 14 days with 50/50 probability
            # imitating a full lifecycle of cybersecurity attack (recon -> ...). Probably, threat actor
            # should look at publishers with large amount of popular packages by likes/downloads/usage/audience
            if self._counter == 14:
                publisher_id: int = random.choice(self._publishers)
                owned_packages = [package for package in self.repo["packages"] if package["owner"] == publisher_id]
                if not owned_packages:
                    self._counter -= 7
                    yield self.env.timeout(1)
                    continue
                
                # try to do attack on multiple packages by creating new major
                # versions of package by these publisher if possible
                compromised_per_package = []
                for i in owned_packages:
                    is_created_artifact = self._create_compromised_artifact(owned_packages=owned_packages)
                    compromised_per_package.append(is_created_artifact)
                
                # at least one package should be compromised
                if not any(compromised_per_package):
                    self._counter -= 7
                    yield self.env.timeout(1)
                    continue

                self._counter = 0
                yield self.env.timeout(1)
            else:
                self._counter += 1
                yield self.env.timeout(1)
    
    # @TODO: copy pasted from Publisher.update_package(),
    # but later we need mechanism to be able to use Publisher instance
    # or his functions not to duplicate functions in multiple places
    def _create_compromised_artifact(self, owned_packages: list):
        package = random.choice(owned_packages)

        if len(package["versions"]) >= self.repo["properties"]["max_package_versions"]:
            return False
        
        # temporary limitation of 9 versions per package
        if len(package["versions"]) >= 9:
            return False

        # create new latest version to corresponding package
        latest_major_version: int = max([int(version["specifier"].split(".")[0]) for version in package["versions"]])
        new_major_latest_version = latest_major_version + 1
        if new_major_latest_version > 9: # temporary limitation of 9 versions per package
            return False
        new_version: Version = {
            "specifier": f"{new_major_latest_version}.0.0",
            "meta_compromised_by": self.id,
            "meta_state": PackageState.COMPROMISED
        }
        package["versions"].append(new_version)
        return True


def software_supply_chain(config: dict):
    """
    Represents activities and environment of software supply chain
    within a closed ecosystem like PyPI repository with multiple actors
    """

    random.seed(config.get("random_seed", 42)) # global random for the program
    env = simpy.Environment()

    # repo is passed by reference as single instance, not a copy and not protected 
    # against race conditions (probably need to use mutexes). Also, old packages
    # with their variations are not deleted (like properties in blockchain data structure),
    # because it leads to loss of traceability (e.g., developer downloaded malware,
    # but cannot check this package on platform on next step).
    package_repository: Repository = {
        "packages": list(),
        "properties": {
            "max_packages": config["max_packages"],
            "max_package_versions": config["max_package_versions"],
            "max_packages_per_publisher": config["max_packages_per_publisher"],
        }
    }

    # @TODO: generating packages for bootrapping
    # (boot field) from configuration
    # for i in range(10):
    #     package = _generate_package()
    #     package_repository["packages"].append(package)
    
    developers = []
    publishers = []
    threat_actors = []
    for i in range(1, config["num_developers"] + 1):
        developer = Developer(env=env, id=i, actions=config["developer_actions"], repo=package_repository, model=config["model"])
        developers.append(developer)
    for i in range(1, config["num_publishers"] + 1):
        publisher = Publisher(env=env, id=i, actions=config["publisher_actions"], repo=package_repository, model=config["model"])
        publishers.append(publisher)
    for i in range(1, config["num_threat_actors"] + 1):
        threat_actor = ThreatActor(env=env, id=i, repo=package_repository, meta_config=config)
        threat_actors.append(threat_actor)

    logger = SimulationLogger(env, package_repository, developers, threat_actors) # @AI_GENERATED_EXPERIMENTAL
    env.process(logger.run()) # @AI_GENERATED_EXPERIMENTAL

    env.run(until = config["max_steps"])

    logger.finalize() # @AI_GENERATED_EXPERIMENTAL

    return logger # @AI_GENERATED_EXPERIMENTAL


# @AI_GENERATED_EXPERIMENTAL
def initial_analyses(logged_data, output_path: pathlib.Path):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    df_steps = pd.DataFrame(logged_data.step_history)

    # --- 1. Dual-Box Trend Analysis ---
    fig_trends, (ax_t1, ax_t2) = plt.subplots(2, 1, figsize=(12, 10), sharex=True)
    
    # Package Trends
    ax_t1.plot(df_steps['step'], df_steps['clear_packages'], label='Clear', color='skyblue', linewidth=2)
    ax_t1.plot(df_steps['step'], df_steps['compromised_packages'], label='Compromised', color='crimson', linewidth=2)
    ax_t1.set_ylabel("Package Count", fontweight='bold')
    ax_t1.set_title("Package Infrastructure Trends", fontsize=14)
    ax_t1.legend(loc='upper left')
    ax_t1.grid(True, linestyle=':', alpha=0.6)

    # Developer Trends
    # Note: Using total developers from logged_data to show clear vs compromised
    total_devs = len(logged_data.developers)
    ax_t2.plot(df_steps['step'], [total_devs - x for x in df_steps['compromised_developers']], label='Clear', color='lightgreen', linewidth=2)
    ax_t2.plot(df_steps['step'], df_steps['compromised_developers'], label='Compromised', color='darkred', linewidth=2)
    ax_t2.set_xlabel("Simulation Step", fontweight='bold')
    ax_t2.set_ylabel("Developer Count", fontweight='bold')
    ax_t2.set_title("Developer Pool Trends", fontsize=14)
    ax_t2.legend(loc='upper left')
    ax_t2.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()
    plt.savefig(output_path / f"trends_dual_{timestamp}.png", dpi=300)
    plt.close()

    # --- 2. Enhanced Node Composition (Integrity Snapshot) ---
    fig_int, (ax_pkg, ax_dev) = plt.subplots(1, 2, figsize=(18, 9))

    def draw_status_graph(ax, clear_list, comp_list, title, clear_color, comp_color):
        G = nx.Graph()
        for item in clear_list: G.add_node(item, status='clear')
        for item in comp_list: G.add_node(item, status='compromised')
        
        if len(G.nodes) == 0:
            ax.text(0.5, 0.5, "No Data", ha='center')
            return

        colors = [clear_color if G.nodes[n]['status'] == 'clear' else comp_color for n in G.nodes]
        pos = nx.spring_layout(G, k=0.15, iterations=20)
        nx.draw_networkx_nodes(G, pos, ax=ax, node_color=colors, node_size=80, alpha=0.8)
        
        # Added requested metrics next to title
        stats_text = f"\nTotal: {len(G.nodes)} | Clear: {len(clear_list)} | Comp: {len(comp_list)}"
        ax.set_title(f"{title}{stats_text}", fontsize=12, fontweight='bold')
        ax.axis('off')

    draw_status_graph(ax_pkg, logged_data.current_clear_packages, logged_data.current_compromised_packages, 
                      "Package Infrastructure State", "skyblue", "crimson")
    draw_status_graph(ax_dev, logged_data.current_clear_developers, logged_data.current_compromised_developers, 
                      "Developer Pool State", "lightgreen", "darkred")

    plt.savefig(output_path / f"integrity_snapshot_{timestamp}.png", dpi=300, bbox_inches='tight')
    plt.close()

    # --- 3. Attack Grid Analysis (Radial Threat Actor View) ---
    threat_actor_ids = sorted(list(set(edge['threat_actor'] for edge in logged_data.attack_edges)))
    num_actors = len(threat_actor_ids)
    
    if num_actors > 0:
        cols = 2
        rows = (num_actors + 1) // 2
        fig_grid, axes = plt.subplots(rows, cols, figsize=(15, 7 * rows))
        axes = axes.flatten() if num_actors > 1 else [axes]

        for i, ta_id in enumerate(threat_actor_ids):
            G_attack = nx.Graph()
            center_node = f"Actor_{ta_id}"
            G_attack.add_node(center_node, type='actor')
            
            # Find packages compromised by THIS specific actor
            actor_packages = [edge['package'] for edge in logged_data.attack_edges if edge['threat_actor'] == ta_id]
            
            for pkg in actor_packages:
                G_attack.add_node(pkg, type='package')
                G_attack.add_edge(center_node, pkg)

            pos = nx.shell_layout(G_attack, nlist=[[center_node], actor_packages])
            
            # Draw Actor
            nx.draw_networkx_nodes(G_attack, pos, nodelist=[center_node], ax=axes[i], 
                                   node_color='red', node_size=500, edgecolors='black')
            # Draw Packages
            nx.draw_networkx_nodes(G_attack, pos, nodelist=actor_packages, ax=axes[i], 
                                   node_color='skyblue', node_size=200, alpha=0.6)
            # Draw Edges
            nx.draw_networkx_edges(G_attack, pos, ax=axes[i], edge_color='gray', alpha=0.3)
            # Labels
            nx.draw_networkx_labels(G_attack, pos, labels={n: n for n in G_attack.nodes}, 
                                    font_size=6, ax=axes[i])
            
            axes[i].set_title(f"Attack Radius: Threat Actor {ta_id}\n({len(actor_packages)} Packages Compromised)", 
                              fontweight='bold', fontsize=11)
            axes[i].axis('off')

        # Clean up empty subplots
        for j in range(i + 1, len(axes)):
            axes[j].axis('off')

        plt.suptitle(f"Separated Threat Analysis - {timestamp}", fontsize=16, y=0.98)
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig(output_path / f"attack_grid_{timestamp}.png", dpi=300)
        plt.close()


def main():
    BASE_DIR = pathlib.Path(__file__).parent

    try:
        with open(str(BASE_DIR / "config.json"), "r") as f: 
            config_file = f.read()
    except OSError: 
        raise
    
    # @TODO: more structured config loading with
    # - validating config for datatypes and fields
    # - find corresponding fields to load in dataclass
    # - fallback to some default values if not specified
    try:
        config = json.loads(config_file)
    except json.JSONDecodeError: 
        raise

    results = software_supply_chain(config)
    initial_analyses(results, BASE_DIR / "data")


if __name__ == "__main__":
    main()
