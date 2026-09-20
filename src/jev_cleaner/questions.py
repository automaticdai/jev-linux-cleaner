"""The seven questions asked about every candidate directory.

The wording here is the contract with the model. Thresholds in policy.yaml were
tuned against this wording and this model version; changing either invalidates
them. Bump BATTERY_VERSION when you change a question, so cached answers from an
older wording are not reused.
"""

from __future__ import annotations

from typesafe_sdk import Choice, Noul, Score

BATTERY_VERSION = "3"

CONTENT_KIND_CRITERIA: dict[str, str] = {
    "regenerable_cache": "Data the program rebuilds or re-downloads by itself the next time it runs.",
    "downloaded_artifacts": "Packages, binaries, browsers or model files fetched over the network, restored only by downloading them again.",
    "build_output": "Compiled objects or build artifacts produced from source code that still exists elsewhere.",
    "transient_runtime_state": "Logs, crash dumps, sockets, pid files and temporary working files.",
    "application_settings": "Configuration and preferences the user set up.",
    "user_content": "Documents, saves, notes, keys or other material the user created or cannot obtain again.",
    "installed_program_files": "The program itself rather than its data.",
    "unclear": "The evidence does not identify what is stored here.",
}
CONTENT_KINDS: tuple[str, ...] = tuple(CONTENT_KIND_CRITERIA)

LOSS_LEVELS: tuple[str, ...] = (
    "Nothing noticeable. The program rebuilds it silently and the user never sees a difference.",
    "A slower next run. The program re-downloads or regenerates the data on its own, costing time or bandwidth but requiring no action from the user.",
    "The user must run a command to restore it, such as re-installing a component or re-downloading a model.",
    "Session or personalization is lost: the user is signed out, or history, preferences and customizations disappear.",
    "Data the user created, or cannot obtain again, is destroyed.",
)


def battery() -> dict[str, Choice | Score | Noul]:
    """All seven questions, asked together against one directory's state."""
    return {
        "content_kind": Choice(
            instructions="What is stored in the directory `directory.path`?",
            criteria=CONTENT_KIND_CRITERIA,
        ),
        "loss_if_deleted": Score(
            instructions=(
                "The directory `directory.path` is deleted, and the software that uses it "
                "is still installed. What does the user lose, and what would the user have "
                "to do to get back to where they were?"
            ),
            criteria=list(LOSS_LEVELS),
        ),
        # The Score above barely separates a shader cache from 2 GB of browsers:
        # asking the model to predict a consequence costs a hop it cannot afford.
        # These two ask what is actually in the directory, which it reads well,
        # and policy derives the restore effort from them in code.
        "holds_installed_payload": Noul(
            instructions=(
                "The contents of `directory.path` are executable programs, browsers, runtimes or "
                "model files that a separate install or download step placed there, rather than "
                "data the program wrote for itself while running."
            ),
        ),
        "fails_until_reinstall": Noul(
            instructions=(
                "With `directory.path` deleted, the software that uses it would report an error "
                "telling the user to install or download something before it could run again."
            ),
        ),
        "breaks_if_deleted": Noul(
            instructions=(
                "Deleting the directory `directory.path` while the software remains installed "
                "would leave that software broken or unable to start until it is reinstalled or repaired."
            ),
        ),
        "recreated_automatically": Noul(
            instructions=(
                "The next time the software runs, it recreates the contents of `directory.path` "
                "by itself, without the user running any command."
            ),
        ),
        "orphaned": Noul(
            instructions=(
                "The directory `directory.path` belongs to software that is no longer installed "
                "on this system."
            ),
            criteria={
                "true": "The software that owns this directory has been removed from the system. `system.possibly_related_installed_software` is empty and the owning software is of a kind that `system.inventory_covers` would list if it were still installed.",
                "false": "The owning software is still present, or it is of a kind `system.inventory_covers` does not list, such as a library, plugin or component bundled inside another program. An empty list on its own is not enough to answer true.",
            },
        ),
        "holds_credentials": Noul(
            instructions=(
                "The directory `directory.path` holds login sessions, cookies, tokens or keys, "
                "so deleting it would sign the user out or require re-authentication."
            ),
        ),
        "privacy_traces": Noul(
            instructions=(
                "The directory `directory.path` holds a record of what the user did: "
                "browsing history, search terms, opened files or command history."
            ),
        ),
    }
