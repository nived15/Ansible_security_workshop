#Check where Ansible config file is located
ansible --version

#Check where Ansible Inventory is located
#sudo vim /etc/ansible/ansible.cfg 
grep snort lab_inventory/hosts

#Ensure snort is installed
ssh ec2-user@snort "sudo snort --version"

#Download all necessary collections and roles
ansible-galaxy install ansible_security.ids_rule
ansible-galaxy install ansible_security.ids_rule_facts
ansible-galaxy install ansible_security.ids_rule
ansible-galaxy install ansible_security.ids_config
ansible-galaxy collection install ibm.qradar
ansible-galaxy collection install ansible.netcommon
ansible-galaxy collection install check_point.mgmt
ls ~/.ansible/roles/ ~/.ansible/collections/ansible_collections/


cat << EOF >> add_snort_rule.yml
- name: Add Snort rule
  hosts: snort
  become: yes

  vars:
    ids_provider: snort

  tasks:
    - name: Add snort password attack rule
      include_role:
        name: "ansible_security.ids_rule"
      vars:
        ids_rule: 'alert tcp any any -> any any (msg:"Attempted /etc/passwd Attack"; uricontent:"/etc/passwd"; classtype:attempted-user; sid:99000004; priority:1; rev:1;)'
        ids_rules_file: '/etc/snort/rules/local.rules'
        ids_rule_state: present
EOF

ansible-playbook -C add_snort_rule.yml

cat << EOF >> verify_attack_rule.yml
---
- name: Verify Snort rule
  hosts: snort
  become: yes

  vars:
    ids_provider: snort

  tasks:
    - name: import ids_rule_facts
      import_role:
        name: 'ansible_security.ids_rule_facts'
      vars:
        ids_rule_facts_filter: 'uricontent:"/etc/passwd"'

    - name: output rules facts
      debug:
        var: ansible_facts.ids_rules
EOF
ansible-playbook -C verify_attack_rule.yml

cat << EOF >> incident_snort_rule.yml
---
- name: Add ids signature for sql injection simulation
  hosts: ids
  become: yes

  vars:
    ids_provider: snort
    protocol: tcp
    source_port: any
    source_ip: any
    dest_port: any
    dest_ip: any

  tasks:
    - name: Add snort sql injection rule
      include_role:
        name: "ansible_security.ids_rule"
      vars:
        ids_rule: 'alert {{protocol}} {{source_ip}} {{source_port}} -> {{dest_ip}} {{dest_port}}  (msg:"Attempted SQL Injection"; uricontent:"/sql_injection_simulation"; classtype:attempted-admin; sid:99000030; priority:1; rev:1;)'
        ids_rules_file: '/etc/snort/rules/local.rules'
        ids_rule_state: present
EOF
ansible-playbook -C incident_snort_rule.yml

cat << EOF >> sql_injection_simulation.yml
---
- name: start sql injection simulation
  hosts: attacker
  become: yes
  gather_facts: no

  tasks:
    - name: simulate sql injection attack every 5 seconds
      shell: "/sbin/daemonize /usr/bin/watch -n 5 curl -m 2 -s http://{{ hostvars['snort']['private_ip2'] }}/sql_injection_simulation"
EOF
ansible-playbook -C sql_injection_simulation.yml

cat << EOF >> incident_snort_log.yml
---
- name: Configure snort for external logging
  hosts: snort
  become: true
  vars:
    ids_provider: "snort"
    ids_config_provider: "snort"
    ids_config_remote_log: true
    ids_config_remote_log_destination: "{{ hostvars['qradar']['private_ip'] }}"
    ids_config_remote_log_procotol: udp
    ids_install_normalize_logs: false

  tasks:
    - name: import ids_config role
      include_role:
        name: "ansible_security.ids_config"

- name: Add Snort log source to QRadar
  hosts: qradar
  collections:
    - ibm.qradar

  tasks:
    - name: Add snort remote logging to QRadar
      qradar_log_source_management:
        name: "Snort rsyslog source - {{ hostvars['snort']['private_ip'] }}"
        type_name: "Snort Open Source IDS"
        state: present
        description: "Snort rsyslog source"
        identifier: "{{ hostvars['snort']['private_ip']|regex_replace('\\\.','-')|regex_replace('^(.*)$', 'ip-\\\1') }}"

    - name: deploy the new log sources
      qradar_deploy:
        type: INCREMENTAL
      failed_when: false
EOF
ansible-playbook -C incident_snort_log.yml 

cat << EOF >> incident_blacklist.yml
---
- name: Blacklist attacker
  hosts: checkpoint

  vars:
    source_ip: "{{ hostvars['attacker']['private_ip2'] }}"
    destination_ip: "{{ hostvars['snort']['private_ip2'] }}"

  tasks:
    - name: Create source IP host object
      checkpoint_host:
        name: "asa-{{ source_ip }}"
        ip_address: "{{ source_ip }}"

    - name: Create destination IP host object
      checkpoint_host:
        name: "asa-{{ destination_ip }}"
        ip_address: "{{ destination_ip }}"

    - name: Create access rule to deny access from source to destination
      checkpoint_access_rule:
        auto_install_policy: yes
        auto_publish_session: yes
        layer: Network
        position: top
        name: "asa-accept-{{ source_ip }}-to-{{ destination_ip }}"
        source: "asa-{{ source_ip }}"
        destination: "asa-{{ destination_ip }}"
        action: drop

    - name: Install policy
      cp_mgmt_install_policy:
        policy_package: standard
        install_on_all_cluster_members_or_fail: yes
      failed_when: false
EOF
ansible-playbook -C incident_blacklist.yml
