# bash completion for hh-lab command
# Install to /etc/bash_completion.d/hh-lab

_hh_lab_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Main commands
    local commands="status logs info help version"

    # Options for logs command
    local logs_opts="-f --follow -n --lines -m --module"

    # If we're completing the first argument (command)
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    # Get the command (first argument)
    local command="${COMP_WORDS[1]}"

    # Completion for logs command
    if [ "$command" = "logs" ]; then
        case "$prev" in
            -m|--module)
                # Complete with available module names from log directory
                local modules=""
                if [ -d "/var/log/hedgehog-lab/modules" ]; then
                    modules=$(cd /var/log/hedgehog-lab/modules 2>/dev/null && ls *.log 2>/dev/null | sed 's/\.log$//' | tr '\n' ' ')
                fi
                COMPREPLY=( $(compgen -W "${modules}" -- ${cur}) )
                return 0
                ;;
            -n|--lines)
                # Suggest common line counts
                COMPREPLY=( $(compgen -W "10 20 50 100 200 500 1000" -- ${cur}) )
                return 0
                ;;
            *)
                # Suggest logs options
                COMPREPLY=( $(compgen -W "${logs_opts}" -- ${cur}) )
                return 0
                ;;
        esac
    fi

    # No completion for other commands
    return 0
}

# Register completion function
complete -F _hh_lab_completions hh-lab
