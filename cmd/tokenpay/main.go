package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/furrberg/chainctl/qweezxc"
	"github.com/gorilla/mux"
)

// global variables that are used to store data from server
var (
	usersSnapshot Users
	UserVisible   User
)

//

// User defines scope of attributes that each user is assigned.
type User struct {
	UserID     int
	Balance    int
	EthAddress common.Address
	privateKey *ecdsa.PrivateKey
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

// Users map of all existing users
type Users map[int]*User

func listener() error {
	tokens := authenticationMiddleware{
		AuthData: make(map[string]string),
	}
	users := make(Users)
	router := mux.NewRouter()

	// router Endpoints
	router.HandleFunc("/users", func(writer http.ResponseWriter, request *http.Request) {
		err := json.NewEncoder(writer).Encode(users)
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

		user := User{
			UserID:     rand.Int(),
			Balance:    0,
			EthAddress: crypto.PubkeyToAddress(key.PublicKey),
			privateKey: key,
		}

		UserVisible = User{
			UserID:     user.UserID,
			Balance:    user.Balance,
			EthAddress: user.EthAddress,
		}

		users[user.UserID] = &user
		tokens.addUser(&user)
		usersSnapshot = users
		err = json.NewEncoder(writer).Encode(UserVisible)
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
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID])
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/check-balance", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID].Balance)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/deposit", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID].EthAddress)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/get-userid", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.UserID == userID {
				err = json.NewEncoder(writer).Encode(users[userID].UserID)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}/get-data", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.UserID == userID {
				usrData := &User{
					UserID:     userID,
					Balance:    users[userID].Balance,
					EthAddress: users[userID].EthAddress,
				}
				err = json.NewEncoder(writer).Encode(usrData)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}).Methods("GET")
	router.HandleFunc("/users/{id}", func(writer http.ResponseWriter, request *http.Request) {
		params := mux.Vars(request)
		userID, err := strconv.Atoi(params["id"])
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.UserID == userID {
				_, ok := users[userID]
				if ok {
					delete(users, userID)
					tokens.deleteUser(user)
				}
			}
		}
		usersSnapshot = users
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

		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.UserID == userID {
				if user.Balance < amount {
					http.Error(writer, "Insufficient balance!", http.StatusInternalServerError)
					return
				}
				if _, ok := users[recipient]; !ok {
					http.Error(writer, "User not found.", http.StatusInternalServerError)
					return
				}
				user.Balance -= amount
				users[recipient].Balance += amount
			}
		}
		usersSnapshot = users
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

		for _, user := range users {
			if user.UserID == userID {
				if user.Balance < amount {
					http.Error(writer, "Insufficient balance!", http.StatusInternalServerError)
					return
				}
				user.Balance -= amount

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

				nonce, err := client.PendingNonceAt(context.Background(), user.EthAddress)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}

				gasPrice, err := client.SuggestGasPrice(context.Background())
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}

				authSpender, err := bind.NewKeyedTransactorWithChainID(user.privateKey, chainID)
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
				authSpender.Nonce = big.NewInt(int64(nonce))
				authSpender.Value = big.NewInt(0) // in wei
				authSpender.GasLimit = uint64(0)  // in units
				authSpender.GasPrice = gasPrice

				nonce, err = client.PendingNonceAt(context.Background(), common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))

				privateKeyOwner, err := crypto.HexToECDSA("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
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

				_, err = instance.Approve(authOwner, user.EthAddress, new(big.Int).SetInt64(int64(amount)))
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}
				_, err = instance.TransferFrom(authSpender, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), recipient, new(big.Int).SetInt64(int64(amount)))
				if err != nil {
					http.Error(writer, err.Error(), http.StatusInternalServerError)
					return
				}

				fmt.Fprintln(writer, "Withdrawn successfully to %v\n", recipient)
				fmt.Fprintln(writer, "New balance: %v\n", user.Balance)
			}
		}
		usersSnapshot = users
	}).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))

	return nil
}

// autoTransfer transfers tokens from user eth addresses to main address every period
func autoTransfer() {
	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		fmt.Errorf(err.Error())
	}

	instance, err := qweezxc.NewQweezxc(common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"), client)
	if err != nil {
		fmt.Println(err)
	}
	for {
		select {
		case <-time.Tick(10 * time.Second):
			for _, v := range usersSnapshot {
				balance, err := instance.BalanceOf(nil, v.EthAddress)
				if err != nil {
					fmt.Println(err)
				}
				if balance.Int64() > 0 {
					chainID, ok := new(big.Int).SetString("31337", 10)
					if !ok {
						fmt.Println(err)
					}

					nonce, err := client.PendingNonceAt(context.Background(), v.EthAddress)
					if err != nil {
						fmt.Println(err)
					}

					gasPrice, err := client.SuggestGasPrice(context.Background())
					if err != nil {
						fmt.Println(err)
					}

					authOwner, err := bind.NewKeyedTransactorWithChainID(v.privateKey, chainID)
					if err != nil {
						fmt.Println(err)
					}
					authOwner.Nonce = big.NewInt(int64(nonce))
					authOwner.Value = big.NewInt(0) // in wei
					authOwner.GasLimit = uint64(0)  // in units
					authOwner.GasPrice = gasPrice

					_, err = instance.Transfer(authOwner, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), balance)
					if err != nil {
						return
					}
					fmt.Printf("Transferred %v tokens successfully to main account from %v\n", balance.Int64(), v.EthAddress)
				}
			}
		}
	}
}

func depositListener() {
	depositEvent := make(chan *qweezxc.QweezxcTransfer)
	client, err := ethclient.Dial("ws://127.0.0.1:8545")
	if err != nil {
		fmt.Errorf(err.Error())
	}

	instance, err := qweezxc.NewQweezxc(common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3"), client)
	if err != nil {
		fmt.Println(err)
	}

	for {
		to := []common.Address{}
		for _, v := range usersSnapshot {
			to = append(to, v.EthAddress)
		}

		from := []common.Address{common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")}

		_, err = instance.WatchTransfer(nil, depositEvent, from, to)
		if err != nil {
			fmt.Println(err.Error())
		}
		for {
			select {
			case tx := <-depositEvent:
				for _, v := range usersSnapshot {
					if v.EthAddress.Hex() == tx.To.Hex() {
						sum := v.Balance
						v.Balance += int(tx.Value.Int64())
						sum = v.Balance - sum
						fmt.Printf("Deposited %v tokens successfully to %v\n", sum, v.UserID)
					}
				}
			}
		}
	}
}

func main() {
	wg := new(sync.WaitGroup)
	wg.Go(autoTransfer)
	err := listener()
	if err != nil {
		fmt.Println(err)
	}
}
