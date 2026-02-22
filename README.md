# Curupira-2 🇧🇷
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/curupira2/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/curupira2?status.png)](http://godoc.org/github.com/pedroalbanese/curupira2)
[![Go Report Card](https://goreportcard.com/badge/github.com/pedroalbanese/curupira2)](https://goreportcard.com/report/github.com/pedroalbanese/curupira2)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/curupira2)](https://github.com/pedroalbanese/curupira2/releases)

## Visão Geral

O **Curupira-2** é um cifrador de bloco involutional desenvolvido para plataformas com recursos limitados (sensores, dispositivos móveis, IoT), baseado no paper de Simplício Jr. et al. ([PiLBA 2008](https://ceur-ws.org/Vol-397/paper8.pdf)).

## Especificações Técnicas

| Parâmetro | Valor |
|-----------|-------|
| Tamanho do bloco | 96 bits (12 bytes) |
| Tamanhos de chave | 96, 144 e 192 bits |
| Número de rodadas | $R = 10$ (96 bits), $R = 12$ (144 bits), $R = 14$ (192 bits) |
| Estrutura | Wide Trail Strategy |

## Organização do Estado

O estado interno é organizado como uma matriz $3 \times 4$ (linhas $\times$ colunas), mapeada por colunas na memória:

$$ 
\begin{bmatrix}
a_{00} & a_{01} & a_{02} & a_{03} \\
a_{10} & a_{11} & a_{12} & a_{13} \\
a_{20} & a_{21} & a_{22} & a_{23}
\end{bmatrix}
$$

Memória: $[a_{00}, a_{10}, a_{20}, a_{01}, a_{11}, a_{21}, a_{02}, a_{12}, a_{22}, a_{03}, a_{13}, a_{23}]$

## Camadas da Rodada

A estrutura de rodada é composta por quatro transformações:

### $\gamma$ - Camada Não-Linear
Aplica a S-Box $S$ (idêntica aos cifradores Anubis e Khazad) a cada byte individualmente:

$$ b_i = S[a_i], \quad i = 0,\ldots,11 $$

### $\pi$ - Camada de Permutação
Permuta os bytes dentro de cada coluna segundo a regra:

$$ b_{i,j} = a_{i,i \oplus j}, \quad 0 \le i < 3, \quad 0 \le j < 4 $$

### $\theta$ - Camada de Difusão Linear
Multiplica cada coluna pela matriz MDS $D$ sobre $\mathrm{GF}(2^8)$:

$$ 
D = \begin{bmatrix}
3 & 2 & 2 \\
4 & 5 & 4 \\
6 & 6 & 7
\end{bmatrix}
$$

Para cada coluna $j \in \{0,1,2,3\}$, com $d = 3j$:

$$ 
\begin{aligned}
v &= \text{xtimes}(a_{0+d} \oplus a_{1+d} \oplus a_{2+d}) \\
w &= \text{xtimes}(v) \\
b_{0+d} &= a_{0+d} \oplus v \\
b_{1+d} &= a_{1+d} \oplus w \\
b_{2+d} &= a_{2+d} \oplus v \oplus w
\end{aligned}
$$

### $\sigma$ - Adição da Chave de Rodada
XOR do estado com a chave de rodada $\kappa^{(r)}$:

$$ b_i = a_i \oplus \kappa_i^{(r)}, \quad i = 0,\ldots,11 $$

## Estrutura das Rodadas

- **Rodada de branqueamento:** $\sigma$ com $\kappa^{(0)}$
- **Rodadas intermediárias:** $\gamma \rightarrow \pi \rightarrow \theta \rightarrow \sigma$
- **Rodada final:** $\gamma \rightarrow \pi \rightarrow \sigma$

## Key Schedule do Curupira-2

### Representação da Chave

A chave é tratada como um elemento do corpo finito $\mathrm{GF}(2^{48t})$, onde:

- $t = 2$ para chaves de 96 bits (12 bytes)
- $t = 3$ para chaves de 144 bits (18 bytes)
- $t = 4$ para chaves de 192 bits (24 bytes)

A chave é representada como um vetor de bytes: $K = (U_{6t-1}, \ldots, U_0)$, onde $U_0$ é o byte menos significativo.

### Polinômios de Redução

Para cada tamanho de chave, um pentanômio primitivo $p_{48t}(x)$ é usado:

$$ 
\begin{aligned}
p_{96}(x) &= x^{96} + x^{16} + x^{13} + x^{11} + 1 \\
p_{144}(x) &= x^{144} + x^{56} + x^{53} + x^{51} + 1 \\
p_{192}(x) &= x^{192} + x^{43} + x^{41} + x^{40} + 1
\end{aligned}
$$

### Constantes de Agenda

As constantes de agenda $q^{(s)}$ são definidas como:

$$ 
\begin{aligned}
q^{(0)} &= 0 \\
q^{(s)} &= (S[s-1], 0, \ldots, 0), \quad s > 0
\end{aligned}
$$

Apenas o byte mais significativo ($U_{6t-1}$) recebe o valor da S-Box.

### Função de Evolução $\Psi_r$

A evolução da chave é definida como:

$$ K^{(r+1)} = \Psi_r(K^{(r)}) = \xi \circ @(K^{(r)} \oplus q^{(r)}) $$

#### Transformação $@$ (multiplicação por $x^8$)

**Para 96 bits (12 bytes):**

$$ @(U_{11},\ldots,U_0) = (U_{10}, \ldots, U_1 \oplus T_1[U_{11}], U_0 \oplus T_0[U_{11}], U_{11}) $$

**Para 144 bits (18 bytes):**

$$ @(U_{17},\ldots,U_0) = (U_{16}, \ldots, U_6 \oplus T_1[U_{17}], U_5 \oplus T_0[U_{17}], \ldots, U_0, U_{17}) $$

**Para 192 bits (24 bytes):**

$$ @(U_{23},\ldots,U_0) = (U_{22}, \ldots, U_5 \oplus T_1[U_{23}], U_4 \oplus T_0[U_{23}], \ldots, U_0, U_{23}) $$

Onde:

$$ 
\begin{aligned}
T_0(u) &= u \oplus (u \gg 5) \oplus (u \gg 3) \\
T_1(u) &= (u \ll 3) \oplus (u \ll 5)
\end{aligned}
$$

#### Transformação $\xi$

$$ 
\xi(u) = v \quad \text{tal que} \quad 
\begin{cases}
V_i = U_{11-i} \oplus U_{12+i}, & \text{se } 0 \le i < 6t-12 \\
V_i = U_i, & \text{caso contrário}
\end{cases}
$$

### Seleção da Chave de Rodada $\phi^*_r$

A chave de rodada efetiva $\kappa^{(r)}$ de 12 bytes é selecionada como:

$$ 
\kappa^{(r)} = \phi^*_r(K^{(r)}), \quad \text{com} \quad 
\begin{cases}
\kappa^{(r)}_{i+3j} = S[K^{(r)}_{i+3j}], & \text{se } i = 0 \\
\kappa^{(r)}_{i+3j} = K^{(r)}_{i+3j}, & \text{caso contrário}
\end{cases}
$$

Apenas os 12 bytes menos significativos de $K^{(r)}$ são utilizados, e a S-Box é aplicada apenas à primeira linha.

## Modos de Operação

### LetterSoup (AEAD)

Modo autenticado que combina cifragem e autenticação baseado no algoritmo descrito no paper.

**Operações:**
- `SetIV(iv)`: inicializa com vetor de inicialização
- `Update(aData)`: processa dados autenticados
- `Encrypt(mData, cData)`: cifra mensagem
- `Decrypt(cData, mData)`: decifra mensagem
- `GetTag(tag, tagBits)`: obtém o tag de autenticação

### Marvin (MAC)

Função MAC baseada no Curupira, utilizada internamente pelo LetterSoup.

**Operações:**
- `Init()`: inicializa com chave
- `InitWithR(R)`: inicializa com valor R
- `Update(aData)`: processa dados
- `GetTag(tag, tagBits)`: obtém o MAC

## Propriedades Criptográficas

- **Efeito avalanche:** Mudança de 1 bit no plaintext afeta aproximadamente 50% dos bits do ciphertext
- **Efeito avalanche na chave:** Mudança de 1 bit na chave afeta aproximadamente 50% dos bits do ciphertext
- **Chaves de rodada:** Todas as $R+1$ chaves de rodada são distintas entre si
- **SCT determinístico:** Square Complete Transform produz o mesmo resultado para a mesma entrada

## Implementação em Go

A implementação segue rigorosamente a especificação do paper, com:

- Interface `cipher.Block` do Go
- Suporte a todos os tamanhos de chave (96, 144, 192 bits)
- LetterSoup e Marvin incluídos
- Testes de propriedades criptográficas (efeito avalanche, chaves de rodada, etc.)

## Status

Implementação baseada estritamente no paper "The Curupira-2 Block Cipher for Constrained Platforms: Specification and Benchmarking" (PiLBA 2008). ~Aguardando vetores de teste oficiais dos autores para validação completa~. Vetores Fornecidos.
