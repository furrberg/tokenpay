package main

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/furrberg/chainctl/qweezxc"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// global variables that are used to store data from server
var (
	UserVisible User
	db          *sql.DB
)

// User defines scope of attributes that each user is assigned.
type User struct {
	UserID     int
	Balance    int
	EthAddress common.Address
	privateKey *ecdsa.PrivateKey
}

func dbInit() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "postgres://admin:admin@localhost:5432/usersdb?sslmode=disable"
	}

	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	// defer sqlDB.Close()
	fmt.Println("Connected to Postgres")

	pingErr := sqlDB.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}
	fmt.Println("Connected!")

	db = sqlDB
}

type authenticationMiddleware struct {
	AuthData map[string]string
}

func (amw *authenticationMiddleware) addUser(usr *User) {
	amw.AuthData[strconv.Itoa(rand.Intn(100))] = strconv.Itoa(usr.UserID)
}

func (amw *authenticationMiddleware) deleteUser(usr *User) {
	for k, v := range amw.AuthData {
		if v == strconv.Itoa(usr.UserID) {
			delete(amw.AuthData, k)
		}
	}
}

func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session-Token")
		if user, found := amw.AuthData[token]; found {
			// found the token in our map
			log.Printf("Authenticated user %s\n", user)
			// Pass down the request to the next middleware (or final handler)
			next.ServeHTTP(w, r)
		} else {
			// Write an error and stop the handler chain
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	})
}

type Request struct {
	Amount      int    `json:"amount"`
	RecipientID int    `json:"recipient_id"`
	EthAddress  string `json:"eth_address"`
}

func listener() error {
	tokens := authenticationMiddleware{
		AuthData: make(map[string]string),
	}
	router := mux.NewRouter()

	// router Endpoints
	router.HandleFunc("/users", func(writer http.ResponseWriter, request *http.Request) {
		users, err := dbUserIterator(db)
		err = json.NewEncoder(writer).Encode(users)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")
	router.HandleFunc("/usernew", func(writer http.ResponseWriter, request *http.Request) {
		key, err := crypto.GenerateKey()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		user := &User{
			UserID:     rand.Intn(100_000_000),
			Balance:    0,
			EthAddress: crypto.PubkeyToAddress(key.PublicKey),
			privateKey: key,
		}

		err = dbAddUser(db, user)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		UserVisible = User{
			UserID:     user.UserID,
			Balance:    user.Balance,
			EthAddress: user.EthAddress,
		}
		tokens.addUser(user)
		err = json.NewEncoder(writer).Encode(UserVisible)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/check-balance", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		user, err := dbGetUser(db, userID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		err = json.NewEncoder(writer).Encode(user.Balance)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/deposit", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		user, err := dbGetUser(db, userID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		err = json.NewEncoder(writer).Encode(user.EthAddress)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/get-data", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		user, err := dbGetUser(db, userID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
		usrData := &User{
			UserID:     userID,
			Balance:    user.Balance,
			EthAddress: user.EthAddress,
		}
		err = json.NewEncoder(writer).Encode(usrData)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		err = dbDeleteUser(db, userID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
	}).Methods("DELETE")
	// http transfer function that allows to transfer available funds to other used id balance
	router.HandleFunc("/users/{id}/transfer", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		var requestBody Request
		err = json.NewDecoder(request.Body).Decode(&requestBody)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		amount := requestBody.Amount
		recipient := requestBody.RecipientID

		user, err := dbGetUser(db, userID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		if user.Balance < amount {
			http.Error(writer, "Insufficient balance!", http.StatusInternalServerError)
			return
		}

		rec, err := dbGetUser(db, recipient)
		if err != nil {
			http.Error(writer, "User not found.", http.StatusInternalServerError)
			return
		}

		user.Balance -= amount
		rec.Balance += amount
		// update user balance in db
		err = dbUpdateBalance(db, user)
		if err != nil {
			http.Error(writer, "User not found.", http.StatusInternalServerError)
			return
		}
		err = dbUpdateBalance(db, rec)
		if err != nil {
			http.Error(writer, "User not found.", http.StatusInternalServerError)
			return
		}
	}).Methods("POST")

	router.HandleFunc("/users/{id}/withdraw", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		requestBody := Request{}
		err := json.NewDecoder(request.Body).Decode(&requestBody)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		amount := requestBody.Amount
		recipient := common.HexToAddress(requestBody.EthAddress)
		user, err := dbGetUser(db, userID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		if user.Balance < amount {
			http.Error(writer, "Insufficient balance!", http.StatusInternalServerError)
			return
		}

		client, err := ethclient.Dial("ws://127.0.0.1:8545")
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		contractAddress := common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")

		instance, err := qweezxc.NewQweezxc(contractAddress, client)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		chainID, ok := new(big.Int).SetString("31337", 10)
		if !ok {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		privateKeyOwner, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		authOwner, err := bind.NewKeyedTransactorWithChainID(privateKeyOwner, chainID)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		authOwner.Nonce = big.NewInt(int64(nonce))
		authOwner.Value = big.NewInt(0) // in wei
		authOwner.GasLimit = uint64(0)  // in units
		authOwner.GasPrice = gasPrice

		_, err = instance.Transfer(authOwner, recipient, new(big.Int).SetInt64(int64(amount)))
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			fmt.Println("1")
			fmt.Println(err)
			return
		}

		user.Balance -= amount
		// update user balance in db
		err = dbUpdateBalance(db, user)
		if err != nil {
			http.Error(writer, "User not found.", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(writer, "Withdrawn successfully to %v\n. New balance: %v\n", recipient, user.Balance)
	}).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))

	return nil
}

// autoTransfer Transfers tokens from user address to main wallet if balance of it is more than 1000 tokens
func autoTransfer() {
	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		log.Fatal(err)
	}

	instance, err := qweezxc.NewQweezxc(common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"), client)
	if err != nil {
		log.Fatal(err)
	}
	for {
		select {
		case <-time.Tick(30 * time.Second):
			users, err := dbUserIterator(db)
			if err != nil {
				log.Fatal(err)
			}
			for _, user := range users {
				balance, err := instance.BalanceOf(nil, user.EthAddress)
				if err != nil {
					log.Fatal(err)
				}
				if balance.Int64() >= 1000 {
					chainID, ok := new(big.Int).SetString("31337", 10)
					if !ok {
						fmt.Println(err)
					}

					privateKey, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
					if err != nil {
						fmt.Println(err)
					}

					nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
					if err != nil {
						fmt.Println(err)
					}

					gasPrice, err := client.SuggestGasPrice(context.Background())
					if err != nil {
						fmt.Println(err)
					}

					fundAmount := big.NewInt(0).Mul(big.NewInt(10_0000), gasPrice) // e.g. 100k gas worth
					fundAmount.Mul(fundAmount, big.NewInt(2))

					txData := new(types.LegacyTx)
					txData.Nonce = nonce
					txData.GasPrice = gasPrice
					txData.To = &user.EthAddress
					txData.Gas = uint64(30000000)
					txData.Value = fundAmount
					txData.Data = []byte{}
					tx := types.NewTx(txData)
					signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
					if err != nil {
						return
					}
					err = client.SendTransaction(context.Background(), signedTx)
					if err != nil {
						log.Fatal(err)
					}

					nonce, err = client.PendingNonceAt(context.Background(), user.EthAddress)
					if err != nil {
						fmt.Println(err)
					}

					gasPrice, err = client.SuggestGasPrice(context.Background())
					if err != nil {
						fmt.Println(err)
					}

					authUser, err := bind.NewKeyedTransactorWithChainID(user.privateKey, chainID)
					if err != nil {
						fmt.Println(err)
					}

					authUser.Nonce = big.NewInt(int64(nonce))
					authUser.Value = big.NewInt(0) // in wei
					authUser.GasLimit = uint64(0)  // in units
					authUser.GasPrice = gasPrice

					_, err = instance.Transfer(authUser, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), balance)
					if err != nil {
						log.Fatal(err)
					}
					fmt.Printf("%v was transfered from %v to main\n", balance, user.EthAddress)
				}
			}
		}
	}
}

// depositListener Listens to all deposit transactions coming onto user public addresses.
func depositListener() {
	depositEvent := make(chan types.Log, 1)
	var transferEvent struct {
		From  common.Address
		To    common.Address
		Value *big.Int
	}

	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		fmt.Errorf(err.Error())
	}

	contractAbi, err := abi.JSON(strings.NewReader(`[{"type":"event","name":"Transfer","inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}]}]`))
	if err != nil {
		fmt.Errorf(err.Error())
	}

	_, err = qweezxc.NewQweezxc(common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"), client)
	if err != nil {
		fmt.Println(err)
	}

	query := ethereum.FilterQuery{
		Addresses: []common.Address{
			common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"),
		},
		Topics: [][]common.Hash{{contractAbi.Events["Transfer"].ID}},
	}

	sub, err := client.SubscribeFilterLogs(context.Background(), query, depositEvent)
	if err != nil {
		log.Fatal(err)
	}
	defer sub.Unsubscribe()

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-depositEvent:
			err = contractAbi.UnpackIntoInterface(&transferEvent, "Transfer", vLog.Data)
			if err != nil {
				log.Fatal(err)
			}
			users, err := dbUserIterator(db)
			if err != nil {
				log.Fatal(err)
			}
			transferEvent.From = common.BytesToAddress(vLog.Topics[1].Bytes())
			transferEvent.To = common.BytesToAddress(vLog.Topics[2].Bytes())
			for _, v := range users {
				if transferEvent.To.Hex() == v.EthAddress.Hex() {
					v.Balance = v.Balance + int(transferEvent.Value.Int64())
					fmt.Printf("Deposited %v tokens successfully\n", transferEvent.Value.Int64())
					fmt.Printf("current balance is %v\n", v.Balance)
					err = dbUpdateBalance(db, v)
					if err != nil {
						fmt.Println(err)
					}
				}
			}
		}
	}
}

func main() {
	wg := new(sync.WaitGroup)
	dbInit()
	wg.Go(depositListener)
	wg.Go(autoTransfer)
	err := listener()
	if err != nil {
		db.Close()
		fmt.Println(err)
	}
}
