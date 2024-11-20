import os
import binascii
def upper(mac):
    novo_mac = ''
    for letra in mac:
        if letra.isalpha():
            novo_mac += letra.upper()
        else:
            novo_mac += letra
    return novo_mac
def ipv4_existencia(quadro):
    diretorio = './IPv4'
    existe = os.path.exists(diretorio)
    if existe == True:
        x = open('IPv4/packet.txt', 'w')
        x.write(quadro[14:])
    else:
        os.makedirs('IPv4')
        x = open('IPv4/packet.txt', 'w')
        x.write(quadro[14:])
def ipv6_existencia(quadro):
    diretorio = './IPv6'
    existe = os.path.exists(diretorio)
    if existe == True:
        x = open('IPv6/packet.txt', 'w')
        x.write(quadro[14:])
    else:
        os.makedirs('IPv6')
        x = open('IPv4/packet.txt', 'w')
        x.write(quadro[14:])
def ARP_existe(quadro):
    diretorio = './ARP'
    existe = os.path.exists(diretorio)
    if existe == True:
        x = open('ARP/arpReply.txt', 'w')
        x.write(quadro[14:])
    else:
        os.makedirs('ARP')
        x = open('ARP/arpReply.txt', 'w')
        x.write(quadro[14:])
def direcionamento(mac_destino, mac_host, quadro):
    aumentar = mac_host.encode('utf-8').hex()#413042314332443345344635
    if mac_destino == aumentar:
        protocol_hex = quadro[24:28]
        if protocol_hex == "0800":
            existe = ipv4_existencia(quadro)
            mac_destino = 0
        elif protocol_hex == "08DD":
            existe = ipv6_existencia(quadro)
            mac_destino = 1
        elif protocol_hex == "0806":
            existe = ARP_existe(quadro)
            mac_destino = 2
        else:
            mac_destino = 3
        return (mac_destino)
    else:
        return str 
def cal_mac_host(configuracao, mac):
    documento = open('netsettings.host.txt', 'r')
    configuracao = documento.readlines()
    for i in range(0, len(configuracao)):
        if "mac" in configuracao[i]:
            mac = configuracao[i+1]
            mac = mac[8:]
            mac = mac.replace(":", "")
            return str(mac)
def verificar_integridade(quadro, configuracao ):
    crc32 = binascii.crc32(quadro.encode('utf-8')) & 0xFFFFFFFF
    if crc32 != 0:#Processando quadro
        mac = quadro[:12]
        destino_mac = binascii.hexlify(mac.encode('utf-8')).decode('utf-8')
        mac=''
        endereco_mac_host = (cal_mac_host(configuracao, mac))
        return (destino_mac, endereco_mac_host)
    else:# crc == 0
        return False
def verificar_existencia(quadro, documento): #def verificar_existencia(quadro, documento, arquivo): 
    #if str(arquivo) in os.listdir("./eth0"):
    if "rframe.txt" in os.listdir("./eth0"):
        quadro = open(quadro)
        configuracao = documento.read().strip()
        quadro= quadro.read()
        return (quadro, configuracao)
    else:
        return False
def abrir_docs():
    documento = open('netsettings.host.txt', 'r')
    pasta = "eth0/-"
    #arquivo = input("Digite o nome do arquivo em 'eth0':")
    #quadro = pasta.replace("-", arquivo)
    quadro = pasta.replace("-", 'rframe.txt')
    return (quadro, documento) #return (quadro, documento, arquivo)
def printar_entrega(encaminhamento):
    if encaminhamento == 0:
        print('Carga útil entregue no protocolo IPv4')
        print('. '* 30)
        print("Apagando arquivo PDU")
        print('-'* 60) 
    elif encaminhamento == 1: 
        print('Carga útil entregue no protocolo IPv6')
        print('. '* 30)
        print("Apagando arquivo PDU")
        print('-'* 60)
    elif encaminhamento == 2:
        print('Carga útil entregue no protocolo ARP')
        print('. '* 30)
        print("Apagando arquivo PDU")
        print('-'* 60)
    else:
        print("Protocolo de Camada 3 desconhecido.")
        print('. '* 30)
        print("Apagando arquivo PDU'") 
        print('-'* 60)
print('-'* 60)
print(" "*8,'DEMONSTRAÇÃO CAMADA 2 DO HOST DESTINATÁRIO')
print('-'* 60)
processamento = ""
while processamento =="":
    docs = abrir_docs()
    x = verificar_existencia(docs[0], docs[1]) #x = verificar_existencia(docs[0], docs[1], docs[2])
    if x != False:
        print("Arquivo Encontrado. Verificando integridade da PDU")
        print('. '* 30)
        calcular = verificar_integridade(x[0], x[1])
        if calcular != False:
            print("PDU íntegro. Verificando destino.")
            print('. '* 30)
            aumentar = upper(calcular[1])#Tranforma a0b1c2d3e4f5 em A0B1C2D3E4F5
            encaminhamento = direcionamento(calcular[0], aumentar, x[0])
            if direcionamento != str:
                print("Endereço de destino corresponde ao host. Verificando")
                print("protocolo da camada 3.")
                print('. '* 30)
                entrega = printar_entrega(encaminhamento)
            else:
                print("Endereço de destino não corresponde ao host. Descartando PDU.")
                print('-'* 60)
        else:
            print("PDU corrompido. Descartando PDU.")
            print('-'* 60)
    else:
        print("Arquivo não encontrado.")
        print('-'* 60)
    os.remove(docs[0])
    continuar = input("Digite enter para processar outra PDU.")
    if continuar =="":
        processamento = continuar
        os.system('clear')
    else:
        processamento = continuar
        os.system('clear')
        print("Todos os direitos reservados. Este conteúdo está protegido por direitos autorais e não pode ser reproduzido, distribuído, transmitido, exibido ou copiado sem a permissão prévia por escrito do detentor dos direitos autorais.©")
        break


#Trabalho 
