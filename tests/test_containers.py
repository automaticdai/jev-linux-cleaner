from jev_cleaner.containers import container_verdicts, parse_docker_size
from jev_cleaner.report import render_plan


def test_docker_sizes_parse_to_bytes():
    assert parse_docker_size("1.5GB") == 1_500_000_000
    assert parse_docker_size("200MB") == 200_000_000
    assert parse_docker_size("1.5GiB") == int(1.5 * 1024 ** 3)
    assert parse_docker_size("0B") == 0
    assert parse_docker_size("12.3kB (virtual 40MB)") == 12_300


def test_dangling_images_and_stopped_containers_become_verdicts():
    outputs = {
        ("docker", "image"): "sha256:aaa\t1.5GB\nsha256:bbb\t500MB\n",
        ("docker", "ps"): "c1\t12.3kB (virtual 40MB)\tolds\n",
        ("docker", "builder"): "Build Cache\t8\t3\t2.1GB\t2.1GB\n",
    }

    def fake_runner(cmd):
        return outputs[(cmd[0], cmd[1])]

    rows = {v.group.path: v for v in container_verdicts(runner=fake_runner)}
    assert rows["docker://dangling-images"].group.size_bytes == 2_000_000_000
    assert rows["docker://dangling-images"].group.file_count == 2
    assert rows["docker://dangling-images"].tier == "clean"
    assert rows["docker://stopped-containers"].group.size_bytes == 12_300
    assert rows["docker://build-cache"].group.size_bytes == 2_100_000_000
    assert all(v.judgment is None for v in rows.values())
    assert all(v.group.scope == "container" for v in rows.values())


def test_nothing_reclaimable_produces_no_rows():
    def empty_runner(cmd):
        return ""

    assert container_verdicts(runner=empty_runner) == []


def test_docker_absent_is_not_an_error():
    def no_docker(cmd):
        raise FileNotFoundError("docker")

    assert container_verdicts(runner=no_docker) == []


def test_plan_uses_docker_prune_not_rm_for_container_rows():
    def fake_runner(cmd):
        return "sha256:aaa\t1.5GB\n" if cmd[1] == "image" else ""

    plan = render_plan(container_verdicts(runner=fake_runner))
    assert "docker image prune -f" in plan
    assert "rm -rf 'docker://" not in plan
