#!/bin/bash
WPR=$(find . -path "./tmp/*" -prune -o -path "*/wp-content/*" -prune -o -type f -name "wp-config.php" -printf '%h\n')

check_wp_conf=wp-config.php


latestv=$(curl -sS 'https://api.github.com/repos/WordPress/WordPress/tags' | grep name | head -n1 | awk -F'"' '{print $4}')

 for D in $(echo "$WPR"); do cd $D;
    if [ -f "$check_wp_conf" ]; then
    echo "-----------------------------------------------------------------------------" && printf '\n'
    echo "Website:$(wp option get home 2>/dev/null)${normal}" && printf '\n'
        echo "App path: $D" && printf '\n'
    echo -n "Core version: $(wp core version --skip-plugins --skip-themes) " && echo "($(wp core check-update --skip-plugins --skip-themes))"
    printf '\n'
    echo  "Plugins for update:" 
        if [[ $(wp plugin status --skip-plugins --skip-themes | grep U) != *"Update Available"* ]]; then
            echo "All plugins are up to date!"
        else
            wp plugin status --skip-plugins --skip-themes | grep U
        fi
    printf '\n'
    echo "Themes for update:"
        if [[ $(wp theme status --skip-plugins --skip-themes | grep U) != *"Update Available"* ]]; then
                        echo "All themes are up to date!"
                else
                        wp theme status --skip-plugins --skip-themes | grep U
                fi
    printf '\n'
    fi
    cd
done