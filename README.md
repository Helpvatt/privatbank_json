# privatbank_json
## License
This project is licensed under the [GNU General Public License v3.0](LICENSE).  
**Note**: Commercial use is prohibited without explicit permission from the author. For commercial use inquiries, please contact [helpvatt@gmail.com].

Реалізація протоколу JSON для терміналів Приватбанку (Україна), через http запити
(стандартна утиліта від ПриватБанку працює через WebSocket що не завжди зручно і ще завантажує процессор)

Працює як веб сервер на порту 8080
На терміналі повинен бути встановлений протокол JSON та статична IP адреса. 
Наразі адреса зашита в код а саме 192.168.0.164 
Для зміни треба редгувати в коді перед збіркою.
В майбутньому планується виведення налаштувань портів і IP в окремий функціонал. 
Також будуть додані приклади коду для роботи з 1С.

Приклад http запиту:

POST /api/terminal HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Content-Length: 166

{
"terminalIp" : "192.168.0.164",  
"method": "Purchase",
"step": 0,
"params": {
"amount": "0.60",
"discount": "",
"merchantId": "0",
"facepay": "false"}
}

//////////////////////////////////////////

Тіло запиту для різних операцій брати з документації до протоколу JSON ПриватБанку


Інструкція по встановленню для Windows
1.Встановити на компьютер NET 6.0 (або інший але з виправленням залежностей перед збіркою в файлі TerminalClientApp.csproj)
2. Обрати папку зДля якої ОС буде збірка , зберегти на компьютер
3. Відкрити папку проекту в командному рядку
4. Виконати команду dotnet publish -c Release -r win-x64 --self-contained true -o C:\Users\User\TerminalClient\publish
5. Папку C:\Users\User\TerminalClient\publish перемістити в Programfiles або в інше місце
6. Створити службу windows  sc create TerminalClientService binPath= "C:\Users\User\TerminalClient\publish\TerminalClient.exe" DisplayName= "Terminal Client Service" start= auto (шлях до виконуваного файлу може відрізнятися)
7. Відкрити порти 8080 і 2000 в бранмаузері

Інструкція по встановленню для Linux
В процессі наповнення.....


Вітаются будь яка допомога  в розвитку проекту 
