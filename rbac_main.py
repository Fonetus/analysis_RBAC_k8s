from kubernetes import client, config
from rbac_parser import RBAC_Parser
import yaml
import argparse

config.load_kube_config()

rbac_api = client.RbacAuthorizationV1Api()

class Roles_of_RBAC:
    def __init__(self, source='api', file_path=None, output_file="rbac_report.txt"):

        self.user_subject_found = {}
        self.group_subject_found = {}
        self.service_account_subject_found = {}

        self.risky_rules = self.load_risky_rules("risky_rules.yaml")

        self.output_file = output_file

        parser = RBAC_Parser()

        if source == 'file' and file_path:
            parser.load_from_file(file_path)
        else:
            parser.load_from_api()

        self.roles = parser.roles
        self.cluster_roles = parser.cluster_roles
        self.role_bindings = parser.role_bindings
        self.cluster_role_bindings = parser.cluster_role_bindings

    def log(self, text=""):
        self.output_file.write(text + "\n")

    # Загрузка risky_rules.yaml файла
    def load_risky_rules(self, yaml_file):

        with open(yaml_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return data.get('items', [])

    # Распределение по субъектам: User, Group, ServiceAccount
    def binding_subject(self, bindings, binding_type) -> None:

        for obj in bindings:
            # Работа с данными, загруженных из файла
            if isinstance(obj, dict):
                subjects = obj.get('subjects', [])
                if not subjects:
                    continue

                for subj in subjects:
                    subj_kind = subj.get('kind')
                    subj_name = subj.get('name')
                    role_ref = obj.get('roleRef', {})
                    role_ref_kind = role_ref.get('kind')
                    role_ref_name = role_ref.get('name')
                    subj_namespace = subj.get('namespace')

                    if subj_kind == "User":
                        if subj_name not in self.user_subject_found:
                            self.user_subject_found[subj_name] = []
                        self.user_subject_found[subj_name].append({
                            "subjects_kind": subj_kind,
                            "roleRef_kind": role_ref_kind,
                            "roleRef_name": role_ref_name,
                            "binding_kind": binding_type
                        })
                    elif subj_kind == "Group":
                        if subj_name not in self.group_subject_found:
                            self.group_subject_found[subj_name] = []
                        self.group_subject_found[subj_name].append({
                            "subjects_kind": subj_kind,
                            "roleRef_kind": role_ref_kind,
                            "roleRef_name": role_ref_name,
                            "binding_kind": binding_type
                        })
                    elif subj_kind == "ServiceAccount":
                        if subj_name not in self.service_account_subject_found:
                            self.service_account_subject_found[subj_name] = []
                        self.service_account_subject_found[subj_name].append({
                            "subjects_kind": subj_kind,
                            "subject_namespace": subj_namespace,
                            "roleRef_kind": role_ref_kind,
                            "roleRef_name": role_ref_name,
                            "binding_kind": binding_type
                        })

            else:
                # Работа с данными, загруженных из API
                if not obj.subjects:
                    continue

                for subj in obj.subjects:
                    if subj.kind == "User":
                        if subj.name not in self.user_subject_found:
                            self.user_subject_found[subj.name] = []
                        self.user_subject_found[subj.name].append({
                            "subjects_kind": subj.kind,
                            "roleRef_kind": obj.role_ref.kind,
                            "roleRef_name": obj.role_ref.name,
                            "binding_kind": binding_type
                        })
                    elif subj.kind == "Group":
                        if subj.name not in self.group_subject_found:
                            self.group_subject_found[subj.name] = []
                        self.group_subject_found[subj.name].append({
                            "subjects_kind": subj.kind,
                            "roleRef_kind": obj.role_ref.kind,
                            "roleRef_name": obj.role_ref.name,
                            "binding_kind": binding_type
                        })
                    elif subj.kind == "ServiceAccount":
                        if subj.name not in self.service_account_subject_found:
                            self.service_account_subject_found[subj.name] = []
                        self.service_account_subject_found[subj.name].append({
                            "subjects_kind": subj.kind,
                            "subject_namespace": subj.namespace,
                            "roleRef_kind": obj.role_ref.kind,
                            "roleRef_name": obj.role_ref.name,
                            "binding_kind": binding_type
                        })

    def role_binding(self) -> None:
        bindings = self.role_bindings if isinstance(self.role_bindings, list) else self.role_bindings.items
        self.binding_subject(bindings, "RoleBinding")

    def cluster_role_binding(self) -> None:
        bindings = self.cluster_role_bindings if isinstance(self.cluster_role_bindings, list) else self.cluster_role_bindings.items
        self.binding_subject(bindings, "ClusterRoleBinding")

    # Определение ролей
    def finding_roles_binding(self, subject_found, dangerous=False) -> None:
        for object, bindings_list in subject_found:
            self.log(f"----Subject's role: {object}\n")

            for binding_info in bindings_list:
                roleRef_kind = binding_info['roleRef_kind']
                roleRef_name = binding_info['roleRef_name']
                binding_kind = binding_info['binding_kind']

                if binding_kind == 'ClusterRoleBinding':
                    self.log(f"Имеет глобальные права (весь кластер)")
                else:
                    self.log(f"Имеет локальные права в namespace")

                if roleRef_kind == 'ClusterRole':
                    self.defining_access_rules(self.cluster_roles, roleRef_name, "ClusterRole", dangerous)
                elif roleRef_kind == 'Role':
                    self.defining_access_rules(self.roles, roleRef_name, "Role", dangerous)

    def finding_users_roles(self, dangerous=False) -> None:
        self.finding_roles_binding(self.user_subject_found.items(), dangerous)

    def finding_groups_roles(self, dangerous=False) -> None:
        self.finding_roles_binding(self.group_subject_found.items(), dangerous)

    def finding_service_accounts_roles(self, dangerous=False) -> None:
        self.finding_roles_binding(self.service_account_subject_found.items(), dangerous)

    # Нахождение правил для роли, проверка на соответствие паттернам
    def defining_access_rules(self, roles_set, roleRef_name, role_kind, dangerous=False):

        for r in roles_set:
            if hasattr(r, 'metadata'):
                # Kubernetes API
                if r.metadata.name == roleRef_name:
                    rules = r.rules or []
                    break
            else:
                # Из файла
                if r.get('metadata', {}).get('name') == roleRef_name:
                    rules = r.get('rules', [])
                    break

        all_matches = []
        dangerous_rules=False

        for rule in rules:

            if isinstance(rule, dict):
                rule_obj = type('Rule', (), {
                    'verbs': rule.get('verbs', []),
                    'resources': rule.get('resources', []),
                    'api_groups': rule.get('apiGroups', [])
                })()
            else:
                rule_obj = rule

            matches = self.check_rule_against_patterns(rule_obj, role_kind)
            all_matches.extend(matches)

            priority = self.get_max_priority(matches)

            if dangerous and priority == "LOW":
                continue

            dangerous_rules = True

            if isinstance(rule, dict):
                verbs = ', '.join(rule.get('verbs', [])) if rule.get('verbs') else ''
                resources = ', '.join(rule.get('resources', [])) if rule.get('resources') else ''
                api_groups = ', '.join(rule.get('apiGroups', [])) if rule.get('apiGroups') else ''
            else:
                verbs = ', '.join(rule.verbs) if rule.verbs else ''
                resources = ', '.join(rule.resources) if rule.resources else ''
                api_groups = ', '.join(rule.api_groups) if rule.api_groups else ''

            self.log(f"[{verbs}] {resources} (apiGroup: {api_groups})")

            if matches:
                for match in matches:
                    self.log(f"Паттерн: {match['pattern_name']} ({match['priority']})")

        if dangerous and not dangerous_rules:
            return

        max_priority = self.get_max_priority(all_matches)
        self.log(f"Уровень опасности: {max_priority}")
        if all_matches == []:
            self.log(f"Сработало паттернов: 0\n")
        else:
            self.log(f"Сработало паттернов: {len(all_matches)}\n")

    #Проверка правила по всем паттернам
    def check_rule_against_patterns(self, rule, role_kind=None):

        matches = []

        rule_verbs = set(rule.verbs or [])
        rule_resources = set(rule.resources or [])
        rule_api_groups = set(rule.api_groups or [])

        for pattern in self.risky_rules:
            pattern_kind = pattern.get('kind')
            if pattern_kind and role_kind and pattern_kind != role_kind:
                continue

            pattern_rules = pattern.get('rules', [])

            for pattern_rule in pattern_rules:
                if self._matches_pattern(rule_verbs, pattern_rule.get('verbs', []),
                                         rule_resources, pattern_rule.get('resources', []),
                                         rule_api_groups, pattern_rule.get('apiGroups', [])):
                    matches.append({
                        'pattern_name': pattern['metadata']['name'],
                        'priority': pattern['metadata']['priority'],
                        'description': pattern['metadata'].get('description', '')
                    })
                    break

        return matches

    #Проверка совпадения паттерна с одним правилом
    def _matches_pattern(self, rule_verbs, pattern_verbs,
                         rule_resources, pattern_resources,
                         rule_api_groups, pattern_api_groups):

        pattern_verbs = set(pattern_verbs)
        pattern_resources = set(pattern_resources)
        pattern_api_groups = set(pattern_api_groups)

        if '*' in pattern_verbs:
            verbs_match = True
        elif '*' in rule_verbs:
            verbs_match = True
        else:
            verbs_match = bool(rule_verbs & pattern_verbs)

        if '*' in pattern_resources:
            resources_match = True
        elif '*' in rule_resources:
            resources_match = True
        else:
            resources_match = bool(rule_resources & pattern_resources)

        if '*' in pattern_api_groups:
            api_match = True
        elif '*' in rule_api_groups:
            api_match = True
        else:
            api_match = bool(rule_api_groups & pattern_api_groups)

        return verbs_match and resources_match and api_match

    def get_max_priority(self, matches):

        priority_order = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}

        if not matches:
            return "LOW"

        max_priority = max(matches, key=lambda m: priority_order.get(m['priority'], 0))
        return max_priority['priority']


    def run(self, output_filename="rbac_report.txt", dangerous=False):
        if output_filename:
            self.output_file = open(output_filename, 'w', encoding='utf-8')
            self.log(f"  ОТЧЕТ RBAC")

        self.role_binding()
        self.cluster_role_binding()

        self.log("\n  SUBJECT USERS")
        self.finding_users_roles(dangerous)

        self.log("\n  SUBJECT GROUPS")
        self.finding_groups_roles(dangerous)

        self.log("\n  SUBJECT SERVICE ACCOUNTS")
        self.finding_service_accounts_roles(dangerous)

        if self.output_file:
            self.output_file.close()
            print("Отчет сохранен в файл rbac_report.txt")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='RBAC')
    parser.add_argument('--source', choices=['api', 'file'], default='api', help='Источник данных: Kubernetes API или file')
    parser.add_argument('--file', type=str, help='Путь к YAML/JSON файлу')
    parser.add_argument('--dangerous', action='store_true', help='Показать только опасные правила')

    args = parser.parse_args()

    role = Roles_of_RBAC(source=args.source, file_path=args.file if args.source == 'file' else None)
    role.run(dangerous=args.dangerous)