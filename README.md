# SOC-Forge

**SOC-Forge** é uma ferramenta de linha de comando (CLI) desenvolvida para analistas de SOC, permitindo a análise de endereços IP com múltiplas fontes de inteligência de ameaças. Oferece interfaces fáceis de usar para análise de IPs, geração de consultas KQL e criação de relatórios simplificados.

![image](https://github.com/user-attachments/assets/8cb60f6d-53d2-48c6-bfef-371813222593)

## Funcionalidades

- 🔍 **Análise de IPs**: Analise endereços IP utilizando diversas fontes de inteligência:
  - VirusTotal
  - AbuseIPDB
  - IPInfo
- 📊 **Interface Interativa**: CLI amigável com saída colorida
- 🔎 **Geração de Consultas KQL**: Gere consultas Kibana para IPs de origem, destino ou ambos
- 📝 **Relatórios Detalhados**: Criação de relatórios completos de análise
- 🛠️ **Configuração Fácil**: Instalação simples com script Python e configuração de ambiente

Exemplos:
Análise VirusTotal
<br>
![image](https://github.com/user-attachments/assets/efefc9e4-95a9-4ca0-acce-dc853ce4ee8f)

Análise AbuseIPDB
<br>
![image](https://github.com/user-attachments/assets/12c1005f-f1e5-4f4c-bf0f-24138edb298c)

Análise IPInfo
<br>
![image](https://github.com/user-attachments/assets/a9670538-ec59-4b22-ae9f-3457207cfee4)

Gerar query KQL (Kibana Query Language)
<br>
![image](https://github.com/user-attachments/assets/b96f0da6-1370-4551-a9dc-ec2f6628e209)

## Pré-requisitos

- Python 3.7 ou superior
- Git (para clonar o repositório)
- Acesso à internet (para consultar as APIs)

## Instalação

1. Clone este repositório:
```powershell
git clone https://github.com/seunomeusuario/soc-forge.git
cd soc-forge
```

2. Crie e ative um ambiente virtual Python (recomendado):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate
```

3. Instale as dependências:
```powershell
pip install -r requirements.txt
```

4. Configure suas chaves de API:
   - Copie o arquivo `.env.example` para `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
   - Edite o arquivo `.env` e substitua as chaves de exemplo com suas chaves reais:
     - [VirusTotal](https://www.virustotal.com/gui/join-us)
     - [AbuseIPDB](https://www.abuseipdb.com/account/api)
     - [IPInfo](https://ipinfo.io/signup)

## Uso

1. Execute o script principal:
```powershell
python query.py
```

2. Use o menu interativo para:
   - Inserir endereços IP (suporta múltiplos formatos)
   - Listar IPs extraídos
   - Analisar IPs usando diferentes serviços:
     - VirusTotal (reputação e análises)
     - AbuseIPDB (histórico de abusos)
     - IPInfo (geolocalização e informações adicionais)
   - Gerar consultas KQL para:
     - IPs de origem
     - IPs de destino
     - Ambos (origem ou destino)
   - Criar relatórios detalhados de análise

## Exemplos de Uso

1. **Análise de um IP:**
   - Cole o IP quando solicitado
   - Escolha a opção de análise desejada
   - Veja os resultados formatados na tela

2. **Análise de múltiplos IPs:**
   - Cole a lista de IPs (um por linha)
   - Pressione Enter duas vezes para finalizar
   - Escolha a opção de análise
   - Os resultados serão exibidos em uma tabela organizada

3. **Geração de Query KQL:**
   - Insira os IPs
   - Escolha o tipo de query (source/destination/both)
   - Copie a query gerada para usar no Kibana

## Dependências

O arquivo `requirements.txt` inclui todas as dependências necessárias:
- python-dotenv (gerenciamento de variáveis de ambiente)
- requests (requisições HTTP para as APIs)
- rich (interface CLI colorida e formatada)

## Contribuindo

1. Faça um fork do repositório
2. Crie sua branch de funcionalidade:
```powershell
git checkout -b feature/NovaFuncionalidade
```
3. Faça commit das alterações:
```powershell
git commit -m "Adiciona nova funcionalidade"
```
4. Envie sua branch:
```powershell
git push origin feature/NovaFuncionalidade
```
5. Abra um Pull Request

## Licença

Este projeto está licenciado sob a Licença MIT — consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

## Agradecimentos

- Agradecimentos ao VirusTotal, AbuseIPDB e IPInfo por suas excelentes APIs
- Construído por analistas de SOC para analistas de SOC
