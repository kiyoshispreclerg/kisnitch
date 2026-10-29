# Checklist da UI

Gerado por `tools/gen-ui-checklist.py` a partir de `upstream/ui/opensnitch/res/*.ui`.
Um widget está *coberto* quando o texto dele aparece em `ui/*.c`, ou quando
`docs/ui-checklist-map.tsv` diz como é coberto (ou por que não, e em que fase entra).

## stats.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `StatsDialog` | QDialog | OpenSnitch Network Statistics | ok | título da janela "Kisnitch Network Statistics" (nome do projeto) |
| `actionsButton` | QPushButton |  | ok | botão "Actions": exportar/importar regras, exportar eventos para CSV, sair (ks_sw_actions_clicked) |
| `prefsButton` | QPushButton |  | ok | botão de preferências do cabeçalho |
| `newRuleButton` | QPushButton | Create a new rule | ok | botão "New" do cabeçalho |
| `fwButton` | QPushButton |  | ok | botão "Firewall" do cabeçalho: abre o diálogo do firewall (ui/fw_dialog.c) |
| `nodeLabel` | QLabel | <html><head/><body><p><span style=" font-size:11pt; font-weight:600;">hostname - 192.168.1.1</span></p></body></html> | ok | rótulo preenchido em tempo de execução |
| `label_2` | QLabel | Status | ok | texto presente |
| `statusLabel` | QLabel | - | ok | rótulo preenchido em tempo de execução |
| `startButton` | QPushButton | Start or Stop interception | ok | Start/Stop do cabeçalho |
| `tabWidget` | QTabWidget |  | ok? | entrada sem texto |
| `cmdNodesBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `nodeActionsButton` | QPushButton |  | ok | Actions do nó (exportar/importar regras) |
| `nodeDeleteButton` | QPushButton | Delete this node | ok | botão Delete do nó |
| `nodePrefsButton` | QPushButton | Show the preferences of this node | ok | abre as preferências na aba Nodes |
| `nodeStartButton` | QPushButton | Start or stop interception of this node | ok | Start/Stop do nó |
| `labelNodeName` | QLabel | <h3>Node</h3> | ok | rótulo preenchido em tempo de execução |
| `labelNodeRAM` | QLabel | RAM, Free: , Total: | ok | rótulo preenchido em tempo de execução |
| `nodeRAMProgress` | QProgressBar |  | ok? | entrada sem texto |
| `labelNodeSwap` | QLabel | Swap, Free: , Total: | ok | rótulo preenchido em tempo de execução |
| `nodeSwapProgress` | QProgressBar |  | ok? | entrada sem texto |
| `labelNodeProcs` | QLabel | Processes: | ok | texto presente |
| `labelNodeLoadAvg` | QLabel | Load average: 0.0, 0.0, 0.0 | ok | rótulo preenchido em tempo de execução |
| `labelNodeUptime` | QLabel | Uptime: | ok | texto presente |
| `labelNodeDetails` | QLabel | daemon: | ok | texto presente |
| `rulesTreePanel` | QTreeWidget |  | divergência 66 | a árvore vira um combo (aplicações, permanentes, temporárias, alertas, firewall); o item "Firewall" mostra as regras de sistema de todos os nós (ui/stats_fw.c), sem os ramos por nó, tabela e cadeia |
| `comboRulesFilter` | QComboBox |  | ok? | entrada sem texto |
| `cmdRulesBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `enableRuleCheck` | QCheckBox | enable | ok | texto presente |
| `editRuleButton` | QPushButton | Edit rule | ok | botão Edit do detalhe de uma regra |
| `delRuleButton` | QPushButton | Delete rule | ok | botão Delete do detalhe de uma regra |
| `cmdHostsBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `cmdProcsBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `cmdProcDetails` | QPushButton |  | ok | botão de detalhes do processo (aba Applications) |
| `cmdAddrsBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `cmdPortsBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `cmdUsersBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `cmdNetstatBack` | QPushButton |  | ok | botão Voltar da aba (GTK_STOCK_GO_BACK) |
| `comboNetstatInterval` | QComboBox |  | ok? | entrada sem texto |
| `comboNetstatNodes` | QComboBox |  | ok? | entrada sem texto |
| `label_9` | QLabel | Protocol | ok | texto presente |
| `comboNetstatProto` | QComboBox |  | ok? | entrada sem texto |
| `label_8` | QLabel | Family | ok | texto presente |
| `comboNetstatFamily` | QComboBox |  | ok? | entrada sem texto |
| `label_10` | QLabel | State | ok | texto presente |
| `comboNetstatStates` | QComboBox |  | ok? | entrada sem texto |
| `label_4` | QLabel | Filter | ok | texto presente |
| `comboAction` | QComboBox |  | ok? | entrada sem texto |
| `filterLine` | QLineEdit | Ex.: firefox | ok? | entrada sem texto |
| `prevButton` | QPushButton |  | n/a | escondido pelo próprio upstream (setVisible(False)); nosso modelo virtual rola |
| `labelRowsCount` | QLabel | 0 | ok | contador de linhas |
| `nextButton` | QPushButton |  | n/a | escondido pelo próprio upstream (setVisible(False)); nosso modelo virtual rola |
| `limitCombo` | QComboBox |  | ok? | entrada sem texto |
| `cmdCleanSql` | QPushButton | Delete all intercepted events | ok | botão Clear (apaga os eventos) |
| `helpButton` | QPushButton |  | ok | botão Help (ks_sw_help_clicked), em diálogo em vez de tooltip |
| `label_5` | QLabel | Connections | ok | texto presente |
| `consLabel` | QLabel | - | ok | rótulo preenchido em tempo de execução |
| `label_7` | QLabel | Dropped | ok | texto presente |
| `droppedLabel` | QLabel | - | ok | rótulo preenchido em tempo de execução |
| `label` | QLabel | Uptime | ok | texto presente |
| `uptimeLabel` | QLabel | - | ok | rótulo preenchido em tempo de execução |
| `label_3` | QLabel | Rules | ok | texto presente |
| `rulesLabel` | QLabel | - | ok | rótulo preenchido em tempo de execução |
| `rxtxLabel` | QLabel | - | n/a | o upstream não a usa (sem referência em stats.py) |
| `label_6` | QLabel | Daemon version | ok | texto presente |
| `daemonVerLabel` | QLabel | - | ok | rótulo preenchido em tempo de execução |

## preferences.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `PreferencesDialog` | QDialog | Preferences | ok | texto presente |
| `tabWidget` | QTabWidget |  | ok? | entrada sem texto |
| `cmdTimeoutUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `spinUITimeout` | QSpinBox |  | ok? | entrada sem texto |
| `cmdTimeoutDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `label` | QLabel | Default timeout | ok | texto presente |
| `popupsCheck` | QCheckBox |  | ok | "Disable pop-ups, only display a notification" |
| `label_16` | QLabel | Disable pop-ups, only display a notification | ok | texto presente |
| `label_2` | QLabel | Action | ok | texto presente |
| `comboUIAction` | QComboBox |  | ok? | entrada sem texto |
| `label_3` | QLabel | Duration | ok | texto presente |
| `comboUIDuration` | QComboBox |  | ok? | entrada sem texto |
| `label_5` | QLabel | Default target | ok | texto presente |
| `comboUITarget` | QComboBox |  | ok? | entrada sem texto |
| `label_4` | QLabel | Default position on screen | ok | texto presente |
| `comboUIDialogPos` | QComboBox |  | ok? | entrada sem texto |
| `showAdvancedCheck` | QCheckBox | <html><head/><body><p>If checked, the pop-ups will be displayed with the advanced view active.</p></body></html> | ok | "Show advanced view by default" |
| `label_17` | QLabel | Show advanced view by default | ok | texto presente |
| `uidCheck` | QCheckBox | User ID | ok | texto presente |
| `dstPortCheck` | QCheckBox | Destination port | ok | texto presente |
| `dstIPCheck` | QCheckBox | Destination IP | ok | texto presente |
| `checkSum` | QCheckBox | checksum | ok | texto presente |
| `label_18` | QLabel | Filter connections also by: | ok | texto presente |
| `labelUIDensity` | QLabel | Theme density scale | qt | densidade do tema Qt |
| `label_19` | QLabel | Language | ok | texto presente |
| `comboUITheme` | QComboBox |  | ok? | entrada sem texto |
| `labelUIScreenFactor` | QLabel | <html><head/><body><p>Scale factor (use ; for multiple displays) <a href="https://github.com/evilsocket/opensnitch/wiki/GUI-known-problems#gui-size-problems-on-4k-monitors"><span style=" text-decoration: underline; color:#0000ff;">More information</span></a></p></body></html> | qt | escala de tela do Qt |
| `cmdUIDensityUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `spinUIDensity` | QSpinBox |  | ok? | entrada sem texto |
| `cmdUIDensityDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `checkAutostart` | QCheckBox | Autostart the GUI upon login | ok | texto presente |
| `cmdRefreshUIUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `spinUIRefresh` | QSpinBox |  | ok? | entrada sem texto |
| `cmdRefreshUIDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `lineUIScreenFactor` | QLineEdit | Use numbers to define a global scale factor for the whole application: 1, 1.2, 1.5, 2, etc ... Use ; to define multiple screens: 1;1.5 etc... | ok? | entrada sem texto |
| `comboUILang` | QComboBox |  | ok? | entrada sem texto |
| `label_27` | QLabel | Refresh interval (seconds) | ok | texto presente |
| `label_21` | QLabel | Theme | ok | texto presente |
| `checkUIAutoScreen` | QCheckBox | Auto screen scale factor | qt | escala automática do Qt |
| `label_33` | QLabel | Qt platform plugin | qt | plugin de plataforma do Qt |
| `comboUIQtPlatform` | QComboBox |  | ok? | entrada sem texto |
| `label_32` | QLabel | Address | ok | texto presente |
| `comboServerAddr` | QComboBox |  | ok? | entrada sem texto |
| `label_20` | QLabel | Max gRPC channel size | ok | texto presente |
| `comboGrpcMsgSize` | QComboBox |  | ok? | entrada sem texto |
| `label_24` | QLabel | Authentication type | ok | texto presente |
| `comboAuthType` | QComboBox |  | ok? | entrada sem texto |
| `label_34` | QLabel | Max server workers | ok | texto presente |
| `label_35` | QLabel | Max server clients | ok | texto presente |
| `label_28` | QLabel | <a href="https://github.com/evilsocket/opensnitch/wiki/Nodes-authentication#nodes-authentication-added-in-v161">More information</a> | ok | link "More information" substituído por dicas nos campos de autenticação |
| `cmdGrpcClientsDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `spinGrpcMaxClients` | QSpinBox |  | ok? | entrada sem texto |
| `cmdGrpcClientsUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `cmdGrpcWorkersDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `spinGrpcMaxWorkers` | QSpinBox |  | ok? | entrada sem texto |
| `cmdGrpcWorkersUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `lineCACertFile` | QLineEdit | Absolute path to the CA cert file | ok? | entrada sem texto |
| `lineCertFile` | QLineEdit | Absolute path to the cert file | ok? | entrada sem texto |
| `lineCertKeyFile` | QLineEdit | Absolute path to the cert key file | ok? | entrada sem texto |
| `groupNotifs` | QGroupBox | Enable | ok | texto presente |
| `radioSysNotifs` | QRadioButton | Use system notifications | ok | texto presente |
| `radioQtNotifs` | QRadioButton | Use Qt notifications | divergência 99 | o GtkStatusIcon do GTK 2 não mostra mensagens: o rádio é "Use the tray icon's alert" (o ícone da bandeja vira alerta); as notificações do sistema vêm com NOTIFY=1 |
| `cmdTestNotifs` | QPushButton | Test | ok | texto presente |
| `checkHideSrcPort` | QCheckBox | Source port | ok | texto presente |
| `checkHideSrcIP` | QCheckBox | Source IP | ok | texto presente |
| `checkHideNode` | QCheckBox | Node | ok | texto presente |
| `checkHideCmdline` | QCheckBox | Command line | ok | texto presente |
| `checkHideAction` | QCheckBox | Action | ok | texto presente |
| `checkHideTime` | QCheckBox | Time | ok | texto presente |
| `checkHideProto` | QCheckBox | Protocol | ok | texto presente |
| `checkHideRule` | QCheckBox | Rule | ok | texto presente |
| `checkHideProc` | QCheckBox | Process | ok | texto presente |
| `checkHidePID` | QCheckBox | PID | ok | texto presente |
| `checkHideDstPort` | QCheckBox | Dest port | ok | texto presente |
| `checkHideDstHost` | QCheckBox | Dest host | ok | texto presente |
| `checkHideDstIP` | QCheckBox | Dest IP | ok | texto presente |
| `checkHideUID` | QCheckBox | UID | ok | texto presente |
| `checkUIRules` | QCheckBox | Don't save/Delete rules of duration | ok | texto presente |
| `comboUIRules` | QComboBox |  | ok? | entrada sem texto |
| `checkApplyToNodes` | QCheckBox | Apply configuration to all nodes | ok | texto presente |
| `comboNodes` | QComboBox |  | ok? | entrada sem texto |
| `label_10` | QLabel | Default action when the GUI is disconnected | ok | texto presente |
| `comboNodeDuration` | QComboBox |  | ok? | entrada sem texto |
| `checkInterceptUnknown` | QCheckBox |  | ok | "Debug invalid connections" |
| `labelNodeDuration` | QLabel | Default duration | ok | texto presente |
| `comboNodeAction` | QComboBox |  | ok? | entrada sem texto |
| `label_15` | QLabel | Address | ok | texto presente |
| `comboNodeAddress` | QComboBox |  | ok? | entrada sem texto |
| `label_12` | QLabel | Debug invalid connections | ok | texto presente |
| `label_13` | QLabel | Process monitor method | ok | texto presente |
| `comboNodeMonitorMethod` | QComboBox |  | ok? | entrada sem texto |
| `checkNodeLogUTC` | QCheckBox |  | ok | "Log UTC timestamps" |
| `label_7` | QLabel | Log file | ok | texto presente |
| `label_23` | QLabel | Log timestamp microseconds | ok | texto presente |
| `comboNodeLogLevel` | QComboBox |  | ok? | entrada sem texto |
| `label_22` | QLabel | Log UTC timestamps | ok | texto presente |
| `label_14` | QLabel | Default log level | ok | texto presente |
| `comboNodeLogFile` | QComboBox |  | ok? | entrada sem texto |
| `checkNodeLogMicro` | QCheckBox |  | ok | "Log timestamp microseconds" |
| `lineNodeCertFile` | QLineEdit | Absolute path to the cert file | ok? | entrada sem texto |
| `label_25` | QLabel | Authentication type | ok | texto presente |
| `comboNodeAuthType` | QComboBox |  | ok? | entrada sem texto |
| `lineNodeCACertFile` | QLineEdit | Absolute path to the CA cert file | ok? | entrada sem texto |
| `checkNodeAuthSkipVerify` | QCheckBox | Don't verify certs | ok | texto presente |
| `comboNodeAuthVerifyType` | QComboBox |  | ok? | entrada sem texto |
| `lineNodeCertKeyFile` | QLineEdit | Absolute path to the cert key file | ok? | entrada sem texto |
| `lineNodeServerCertFile` | QLineEdit | Absolute path to the server cert file | ok? | entrada sem texto |
| `label_26` | QLabel | <a href="https://github.com/evilsocket/opensnitch/wiki/Nodes-authentication#nodes-authentication-added-in-v161">More information</a> | ok | link "More information" substituído por dicas nos campos de autenticação |
| `radioButton` | QRadioButton | md5 | ok | texto presente |
| `radioButton_2` | QRadioButton | sha1 | ok | texto presente |
| `enableChecksums` | QCheckBox | Enable checksums verification | ok | texto presente |
| `cmdNodeRulesPath` | QPushButton | Path | ok | texto presente |
| `lineNodeRulesPath` | QLineEdit | If empty, default rules path will be /etc/opensnitchd/rules | ok? | entrada sem texto |
| `lineNodeMaxStats` | QLineEdit | 50 | ok | texto presente |
| `label_31` | QLabel | Max events | ok | texto presente |
| `label_29` | QLabel | Garbage collector percentage | ok | texto presente |
| `lineNodeMaxEvents` | QLineEdit | 250 | ok | texto presente |
| `checkNodeFlushConns` | QCheckBox | Flush connections on start | ok | texto presente |
| `label_30` | QLabel | Max stats | ok | texto presente |
| `cmdNodeGcDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `spinNodeGC` | QSpinBox |  | ok? | entrada sem texto |
| `cmdNodeGcUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `label_11` | QLabel | Firewall rules monitoring interval (seconds) | ok | texto presente |
| `lineNodeFwMonInterval` | QLineEdit | 10s, 15s, 60s, etc | ok? | entrada sem texto |
| `checkNodeBypassQueue` | QCheckBox | Block outbound network traffic if the daemon unexpectedly dies | ok | texto presente |
| `label_9` | QLabel | Version | ok | texto presente |
| `label_8` | QLabel | HostName | ok | texto presente |
| `comboDBType` | QComboBox |  | ok? | entrada sem texto |
| `label_6` | QLabel | Database type | ok | texto presente |
| `dbFileButton` | QPushButton | Select | ok | texto presente |
| `spinDBMaxDays` | QSpinBox |  | ok? | entrada sem texto |
| `cmdDBMaxDaysUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `labelDBPurgeMinutes` | QLabel | minutes | ok | texto presente |
| `spinDBPurgeInterval` | QSpinBox |  | ok? | entrada sem texto |
| `labelDBPurgeInterval` | QLabel | Minutes between events purges | ok | texto presente |
| `labelDBPurgeDays` | QLabel | days | ok | texto presente |
| `checkDBMaxDays` | QCheckBox | Maximum days of events to keep | ok | texto presente |
| `cmdDBMaxDaysDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `cmdDBPurgesUp` | QPushButton |  | ok | setas do GtkSpinButton |
| `cmdDBPurgesDown` | QPushButton |  | ok | setas do GtkSpinButton |
| `checkDBJrnlWal` | QCheckBox | Enable DB Write-Ahead Logging (WAL) | ok | texto presente |
| `helpButton` | QPushButton |  | ok | botão Help |
| `cancelButton` | QPushButton | Close | ok | texto presente |
| `applyButton` | QPushButton | Apply | ok | texto presente |
| `acceptButton` | QPushButton | Save | ok | texto presente |

## ruleseditor.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `RulesDialog` | QDialog | Rule | ok | texto presente |
| `ruleDescEdit` | QPlainTextEdit | Description... | ok? | entrada sem texto |
| `tabWidget` | QTabWidget |  | ok? | entrada sem texto |
| `procLine` | QLineEdit | <html><head/><body><p>The value of this field is always the absolute path to the executable: /path/to/binary<br/></p><p>Examples:</p><p>- Simple: /path/to/binary</p><p>- Multiple paths: ^/usr/lib(64\|)/firefox/firefox$</p><p>- Multiple binaries: ^(/usr/sbin/ntpd\|/lib/systemd/systemd-timesyncd\|/usr/bin/xbrlapi\|/usr/bin/dirmngr)$ </p><p>- Deny/Allow executions from /tmp:</p><p>^/(var/\|)tmp/.*$<br/></p><p>For more examples visit the <a href="https://github.com/evilsocket/opensnitch/wiki/Rules-examples">wiki page</a> or ask on the <a href="https://github.com/evilsocket/opensnitch/discussions">Discussion forums</a>.</p></body></html> | ok? | entrada sem texto |
| `checkCmdlineRegexp` | QCheckBox | Is regular expression | ok | texto presente |
| `uidCheck` | QCheckBox | From this user ID | ok | texto presente |
| `cmdlineCheck` | QCheckBox | From this command line | ok | texto presente |
| `cmdlineLine` | QLineEdit | <html><head/><body><p>This field will contain and match the command line that was executed by the user.<br/></p><p>If the user typed the command, only the command will appear:</p><p>telnet 1.2.3.4<br/></p><p>If the user typed the absolute or relative path to the command, that is what will appear:</p><p>/usr/bin/telnet 1.2.3.4</p><p>../../../usr/bin/telnet 1.2.3.4</p></body></html> | ok? | entrada sem texto |
| `pidCheck` | QCheckBox | From this PID | ok | texto presente |
| `pidLine` | QLineEdit |  | ok? | entrada sem texto |
| `uidCombo` | QComboBox |  | ok? | entrada sem texto |
| `procCheck` | QCheckBox | From this executable | ok | texto presente |
| `checkProcRegexp` | QCheckBox | is regular expression | ok | texto presente |
| `ifaceCombo` | QComboBox |  | ok? | entrada sem texto |
| `protoCombo` | QComboBox | <html><head/><body><p>Only TCP, UDP or UDPLITE are allowed</p><p>You can use regexp, i.e.: ^(TCP\|UDP)$</p></body></html> | ok? | entrada sem texto |
| `dstHostLine` | QLineEdit | Commas or spaces are not allowed to specify multiple domains. Use regular expressions instead: .*(opensnitch\|duckduckgo).com .*\.google.com or a single domain: www.gnu.org - it'll only match www.gnu.org, nor ftp.gnu.org, nor www2.gnu.org, ... gnu.org - it'll only match gnu.org, nor www.gnu.org, nor ftp.gnu.org, ... | ok? | entrada sem texto |
| `dstIPCheck` | QCheckBox | To this IP / Network | ok | texto presente |
| `protoCheck` | QCheckBox | Protocol | ok | texto presente |
| `srcIPCombo` | QComboBox | You can specify a single IP: - 192.168.1.1 or a regular expression: - 192\.168\.1\.[0-9]+ multiple IPs: - ^(192\.168\.1\.1\|172\.16\.0\.1)$ You can also specify a subnet: - 192.168.1.0/24 Note: Commas or spaces are not allowed to separate IPs or networks. | ok? | entrada sem texto |
| `srcIPCheck` | QCheckBox | From this IP / Network | ok | texto presente |
| `dstHostCheck` | QCheckBox | To this host | ok | texto presente |
| `dstIPCombo` | QComboBox | You can specify a single IP: - 192.168.1.1 or a regular expression: - 192\.168\.1\.[0-9]+ multiple IPs: - ^(192\.168\.1\.1\|172\.16\.0\.1)$ You can also specify a subnet: - 192.168.1.0/24 Note: Commas or spaces are not allowed to separate IPs or networks. | ok? | entrada sem texto |
| `ifaceCheck` | QCheckBox | Network interface | ok | texto presente |
| `srcPortCheck` | QCheckBox | From this port | ok | texto presente |
| `srcPortLine` | QLineEdit | <html><head/><body><p>You can specify multiple ports using regular expressions:</p><p>- 53, 80 or 443:</p><p>^(53\|80\|443)$</p><p><br/></p><p>- 53, 443 or 5550 to 5559, etc:</p><p>^(53\|443\|555[0-9])$</p></body></html> | ok? | entrada sem texto |
| `dstPortCheck` | QCheckBox | To this port | ok | texto presente |
| `dstPortLine` | QLineEdit | <html><head/><body><p>You can specify multiple ports using regular expressions:</p><p>- 53, 80 or 443:</p><p>^(53\|80\|443)$</p><p><br/></p><p>- 53, 443 or 5551, 5552, 5553, etc:</p><p>^(53\|443\|555[0-9])$</p></body></html> | ok? | entrada sem texto |
| `dstListNetsCheck` | QCheckBox | To this list of network ranges | ok | texto presente |
| `dstListIPsCheck` | QCheckBox | To this list of IPs | ok | texto presente |
| `selectIPsListButton` | QPushButton |  | ok | botão de abrir diretório da lista de IPs |
| `dstListIPsLine` | QLineEdit | <html><head/><body><p>Select a directory with files containing list of IPs to block or allow:</p><p>1.2.3.4.5</p><p>1.2.3.4.6</p><p>.</p><p>etc.</p><p>One IP per line. Empty lines or started with # are ignored.</p></body></html> | ok? | entrada sem texto |
| `dstListsCheck` | QCheckBox | To this list of domains | ok | texto presente |
| `selectNetsListButton` | QPushButton |  | ok | botão de abrir diretório da lista de redes |
| `dstListNetsLine` | QLineEdit | <html><head/><body><p>Select a directory with files containing list of network ranges to block or allow:</p><p>1.2.3.0/24</p><p>80.34.56.0/20</p><p>.</p><p>etc.<br/></p><p>One Network Range per line. Empty lines or started with # are ignored.</p></body></html> | ok? | entrada sem texto |
| `selectListButton` | QPushButton |  | ok | botão de abrir diretório da lista de domínios |
| `dstListsLine` | QLineEdit | <html><head/><body><p>Select a directory with lists of domains to block or allow.</p><p>Put inside that directory files with any extension containing lists of domains.</p><p><br/>The format of each entry of a list is as follow (hosts format):</p><p>127.0.0.1 www.domain.com</p><p>or </p><p>0.0.0.0 www.domain.com</p><p>Empty lines or started with # are ignored.</p></body></html> | ok? | entrada sem texto |
| `dstListRegexpCheck` | QCheckBox | To this list of domains (regular expressions) | ok | texto presente |
| `selectListRegexpButton` | QPushButton |  | ok | botão de abrir diretório da lista de regex |
| `dstRegexpListsLine` | QLineEdit | <html><head/><body><p>Select a directory with files containing regular expressions of domains to block or allow:</p><p>.*\.example\.com</p><p>You can also use a domain as is: &quot;example.com&quot; , and it'll match whatever.example.com, whatever.example.com.localdomain, etc.</p><p>One domain per line. Empty lines or started with # are ignored.</p></body></html> | ok? | entrada sem texto |
| `md5Check` | QCheckBox | md5 | ok | texto presente |
| `md5Line` | QLineEdit |  | ok? | entrada sem texto |
| `sensitiveCheck` | QCheckBox | Case-sensitive | ok | texto presente |
| `nologCheck` | QCheckBox | Don't log connections | ok | texto presente |
| `pushButton` | QPushButton | These options are experimental / in development, they may have bugs or not be completely finished. Feedback is welcome | n/a | só tooltip de aviso "experimental", sem ação |
| `label` | QLabel | In development | ok | texto presente |
| `precedenceCheck` | QCheckBox | Priority rule | ok | texto presente |
| `ruleNameEdit` | QLineEdit | The rules are checked in alphabetical order, so you can name them accordingly to prioritize them. 000-allow-localhost 001-deny-broadcast ... | ok? | entrada sem texto |
| `label_2` | QLabel | Action | ok | texto presente |
| `label_4` | QLabel | Duration | ok | texto presente |
| `durationCombo` | QComboBox |  | ok? | entrada sem texto |
| `actionDenyRadio` | QRadioButton | Deny | ok | texto presente |
| `actionRejectRadio` | QRadioButton | Reject | ok | texto presente |
| `actionAllowRadio` | QRadioButton | Allow | ok | texto presente |
| `enableCheck` | QCheckBox | Enable | ok | texto presente |
| `nodesCombo` | QComboBox |  | ok? | entrada sem texto |
| `nodeApplyAllCheck` | QCheckBox | Apply rule to all nodes | ok | texto presente |

## prompt.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `Dialog` | QDialog | Dialog | ok | texto presente |
| `whatCombo` | QComboBox |  | ok? | entrada sem texto |
| `durationCombo` | QComboBox |  | ok? | entrada sem texto |
| `actionButton` | QToolButton | action | ok | texto presente |
| `allowButton` | QPushButton | Allow | ok | texto presente |
| `checkAdvanced` | QPushButton | + | ok | botão "+" do modo avançado (set_advanced) |
| `cmdBack` | QPushButton |  | ok | botão Voltar da visão avançada |
| `connDetails` | QPlainTextEdit |  | ok? | entrada sem texto |
| `comboChecksumRule` | QComboBox |  | ok? | entrada sem texto |
| `cmdBackChecksums` | QPushButton |  | ok | botão Voltar da visão de checksums |
| `cmdUpdateRule` | QPushButton | Update rule | ok | texto presente |
| `cmdUpdateRuleAll` | QPushButton | Update All | ok | texto presente |
| `messageLabel` | QLabel | Chromium Web Browser wants to connect to www.evilsocket.net on tcp port 443. And maybe to www.goodsocket.net on port 344 | ok | rótulo preenchido em tempo de execução |
| `cmdInfo` | QPushButton |  | ok | botão de informação do processo |
| `appNameLabel` | QLabel | Chromium Web Browser | ok | rótulo preenchido em tempo de execução |
| `argsLabel` | QLabel | chromium -arg1 -arg2 | ok | rótulo preenchido em tempo de execução |
| `appDescriptionLabel` | QLabel | <html><head/><body><p>/opt/google/chrome/bin/chrome --something abc --more-long def --for-word-wrapping</p></body></html> | ok | rótulo preenchido em tempo de execução |
| `appPathLabel` | QLabel | (/absolute/path/to/bin/chromium) | ok | rótulo preenchido em tempo de execução |
| `label_2` | QLabel | <html><head/><body><p><span style=" font-weight:600;">Executed from</span></p></body></html> | ok | rótulo preenchido em tempo de execução |
| `checkSum` | QCheckBox |  | ok | filtro por checksum |
| `checksumLabel` | QLabel | TextLabel | ok | rótulo preenchido em tempo de execução |
| `checkUserID` | QCheckBox |  | ok | filtro por user id |
| `label_6` | QLabel | User ID | ok | texto presente |
| `checkDstPort` | QCheckBox |  | ok | filtro por porta de destino |
| `label_3` | QLabel | Destination IP | ok | texto presente |
| `destIPLabel` | QLabel | TextLabel | ok | rótulo preenchido em tempo de execução |
| `checksumLabel_2` | QLabel | Checksum | ok | texto presente |
| `uidLabel` | QLabel | TextLabel | ok | rótulo preenchido em tempo de execução |
| `whatIPCombo` | QComboBox |  | ok? | entrada sem texto |
| `checkDstIP` | QCheckBox |  | ok | filtro por IP de destino |
| `destPortLabel_1` | QLabel | Destination Port | ok | texto presente |
| `destPortLabel` | QLabel | TextLabel | ok | rótulo preenchido em tempo de execução |
| `label` | QLabel | Source IP | ok | texto presente |
| `sourceIPLabel` | QLabel | TextLabel | ok | rótulo preenchido em tempo de execução |

## process_details.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `ProcessDetailsDialog` | QDialog | Process details | ok | texto presente |
| `labelProcName` | QLabel | loading... | ok | texto presente |
| `labelProcPath` | QLabel | TextLabel | ok | rótulo preenchido em tempo de execução |
| `labelProcArgs` | QLabel | loading... | ok | texto presente |
| `labelCwd` | QLabel | CWD: loading... | ok | rótulo preenchido em tempo de execução |
| `labelStatm` | QLabel | mem stats: loading... | ok | rótulo preenchido em tempo de execução |
| `tabWidget` | QTabWidget |  | ok? | entrada sem texto |
| `textStatus` | QPlainTextEdit |  | ok? | entrada sem texto |
| `checkFilterSockets` | QCheckBox | Filter sockets | ok | texto presente |
| `checkFilterFiles` | QCheckBox | Filter files | ok | texto presente |
| `textOpenedFiles` | QPlainTextEdit |  | ok? | entrada sem texto |
| `textIOStats` | QPlainTextEdit |  | ok? | entrada sem texto |
| `textMappedFiles` | QPlainTextEdit |  | ok? | entrada sem texto |
| `textStack` | QPlainTextEdit |  | ok? | entrada sem texto |
| `textEnv` | QPlainTextEdit |  | ok? | entrada sem texto |
| `label` | QLabel | Application pids | ok | texto presente |
| `comboPids` | QComboBox |  | ok? | entrada sem texto |
| `cmdAction` | QPushButton | Start or stop monitoring this process | ok | botão Start/Pause do monitoramento do processo |
| `cmdClose` | QPushButton | Close | ok | texto presente |

## firewall.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `Dialog` | QDialog | Firewall | ok | texto presente |
| `tabWidget` | QTabWidget |  | ok? | entrada sem texto |
| `label_2` | QLabel | <html><head/><body><p><span style=" font-size:14pt; font-weight:600;">Firewall</span></p></body></html> | ok | título "Firewall" do diálogo (ui/fw_dialog.c) |
| `sliderFwEnable` | QSlider |  | ok | um check "Enable" no lugar do slider |
| `cmdAllowINService` | QPushButton | Allow service (IN) | ok | "Allow service (IN)": o diálogo de regra em modo exclude_service(IN) |
| `cmdAllowOUTService` | QPushButton | Allow service (OUT) | ok | "Allow service (OUT)": exclude_service(OUT) |
| `cmdNewRule` | QPushButton | New rule | ok | texto presente |
| `comboOutput` | QComboBox |  | ok? | entrada sem texto |
| `label_3` | QLabel | Inbound | ok | rótulo "Inbound" |
| `comboProfile` | QComboBox |  | ok? | entrada sem texto |
| `lblProfile` | QLabel | Profile | ok | escondido, como no upstream (os perfis predefinidos são um TODO lá) |
| `label_4` | QLabel | Outbound | ok | texto presente |
| `comboInput` | QComboBox |  | ok? | entrada sem texto |
| `comboNodes` | QComboBox |  | ok? | entrada sem texto |
| `cmdHelp` | QPushButton |  | ok | abre a página System-rules do wiki |
| `cmdClose` | QPushButton | Close | ok | texto presente |

## firewall_rule.ui

| widget | classe | texto | estado | nota |
|---|---|---|---|---|
| `Dialog` | QDialog | Firewall rule | ok | texto presente |
| `labelNode` | QLabel | Node | ok | texto presente |
| `comboNodes` | QComboBox |  | ok? | entrada sem texto |
| `checkEnable` | QCheckBox | Enable | ok | texto presente |
| `label` | QLabel | Description | ok | texto presente |
| `lineDescription` | QLineEdit |  | ok? | entrada sem texto |
| `tabWidget` | QTabWidget |  | ok? | entrada sem texto |
| `cmdAddStatement` | QPushButton | Add new condition | ok | botão "+" (ui/fw_rule_dialog.c); cada condição é um expander, no lugar das páginas do QToolBox |
| `cmdDelStatement` | QPushButton | Remove selected condition | ok | botão "-": remove a condição aberta |
| `label_3` | QLabel | Direction | ok | rótulo "Direction" |
| `comboDirection` | QComboBox |  | ok? | entrada sem texto |
| `label_4` | QLabel | Action | ok | texto presente |
| `comboVerdict` | QComboBox |  | ok? | entrada sem texto |
| `comboVerdictParms` | QComboBox |  | ok? | entrada sem texto |
| `lineVerdictParms` | QLineEdit | depending on the Action (i.e.: target), the syntaxis of the parameters will vary. Some examples: QUEUE -> num 0 (or 1, 2, ...) REDIRECT, TPROXY, DNAT, SNAT, MASQUERADE: to :22 to 192.168.1.254:8080 to 192.168.1.254 to 1024-2048 (masquerade) | ok? | entrada sem texto |
| `helpButton` | QPushButton |  | ok | o texto de ajuda num diálogo, em vez de tooltip no cursor |
| `cmdDelete` | QPushButton | Delete | ok | texto presente |
| `cmdReset` | QPushButton | Clear | ok | texto presente |
| `cmdClose` | QPushButton | Close | ok | texto presente |
| `cmdSave` | QPushButton | Save | ok | texto presente |
| `cmdAdd` | QPushButton | Add | ok | texto presente |

Total: 356 widgets, 0 sem resposta.
