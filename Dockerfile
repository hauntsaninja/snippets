FROM ubuntu:24.04@sha256:562456a05a0dbd62a671c1854868862a4687bf979a96d48ae8e766642cd911e8

ARG TARGETARCH

SHELL ["/bin/bash", "-c"]

RUN <<EOF
    set -eux
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install --yes unattended-upgrades
    unattended-upgrade
    rm -rf /var/lib/apt/lists/*
EOF

RUN apt-get update && apt-get install --yes \
    # dev
    git build-essential make \
    curl wget \
    vim less \
    ripgrep hyperfine jq zsh tree \
    screen tmux \
    # debug
    gdb strace lsof htop \
    # ps, top, uptime, vmstat
    procps \
    # perf
    linux-tools-common linux-tools-generic \
    # dmesg, lscpu
    util-linux \
    numactl \
    tcpdump \
    net-tools \
    # many interesting things
    bpfcc-tools

RUN <<EOF
    # don't use default profile because rust docs are large
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal --component rustfmt --component clippy
EOF

RUN <<EOF
    set -eux
    printf 'export LC_ALL=C.UTF-8\nexport LANG=C.UTF-8' > /etc/profile.d/locale.sh
    printf '
export PYTHONUNBUFFERED=1
export PYTHONFAULTHANDLER=1
export RUST_BACKTRACE=1
' > /etc/profile.d/custom.sh
EOF

RUN <<EOF
    set -eux
    mkdir -p /tmp/hauntsaninja; cd /tmp/hauntsaninja
    git clone https://github.com/hauntsaninja/personal_setup/

    apt-get install --yes python3-pip python3-venv
    python3 -m venv /venv
    printf 'export PATH=/venv/bin:$PATH' > /etc/profile.d/venv.sh

    # Just in case a non-login shell is used
    ln -s /venv/bin/python /usr/local/bin/python
    ln -s /venv/bin/python3 /usr/local/bin/python3
    ln -s /venv/bin/pip /usr/local/bin/pip

    # As an alternative to using distro Python:
    # source personal_setup/python_setup.sh
    # PYTHON_VERSION=3.12.6
    # python_setup $PYTHON_VERSION
    # ln -s $HOME/.pyenv/versions/$PYTHON_VERSION/bin/python /usr/local/bin/python
    # ln -s $HOME/.pyenv/versions/$PYTHON_VERSION/bin/python /usr/local/bin/python3
    # ln -s $HOME/.pyenv/versions/$PYTHON_VERSION/bin/pip /usr/local/bin/pip
EOF

RUN <<EOF
    set -eux
    source /venv/bin/activate
    python -m pip install --no-cache-dir --upgrade pip uv
    cd /tmp/hauntsaninja
    python personal_setup/run.py --yes zsh vim ubuntu_stuff python_tools misc
    uv pip install --compile --python $(which python) \
        pypyp ipdb ipython psutil jupyter
EOF

# Ensure the entrypoint also sources /etc/profile
RUN <<EOF
    set -eux
    printf '#!/bin/sh -l\nexec "$@"\n' > /setup-env
    chmod +x /setup-env
EOF
ENTRYPOINT ["/setup-env"]
CMD ["/bin/zsh"]
