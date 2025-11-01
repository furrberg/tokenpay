package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

var (
	userID      int
	recipientID int
	ethAddress  string
	amount      int
	url         string
	userVisible Usr
)

type Usr struct {
	UserID     int
	Balance    int
	EthAddress common.Address
	privateKey *ecdsa.PrivateKey
}

var rootCmd = &cobra.Command{
	Use:   "tokenpay",
	Short: "tokenpay is a tool for interacting with tokenpay",
}

// createUserCmd creates new user struct instance with 0 balance and adds it to the map of all users
var createUserCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a user",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := http.Get("http://localhost:8080/usernew")
		if err != nil {
			return err
		}
		err = json.NewDecoder(resp.Body).Decode(&userVisible)
		if err != nil {
			return err
		}
		fmt.Printf("User registered with ID %d and Address %v\n", userVisible.UserID, userVisible.EthAddress.Hex())
		return nil
	},
}

// transferCmd Used to transfer funds from one user id to another
var transferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Transfer tokens",
	RunE:  transfer,
}

type Request struct {
	Amount      int    `json:"amount"`
	RecipientID int    `json:"recipient_id"`
	EthAddress  string `json:"eth_address"`
}

func transfer(cmd *cobra.Command, args []string) error {
	url = "http://localhost:8080/users/" + strconv.Itoa(userID) + "/transfer"
	requestBody := Request{
		Amount:      amount,
		RecipientID: recipientID,
	}

	bytesObj, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	body := bytes.NewBuffer(bytesObj)

	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("%v was succesfuly sent to %v\n", amount, recipientID)

	return nil
}

var withdrawCmd = &cobra.Command{
	Use:   "withdraw",
	Short: "Withdraw tokens",
	RunE:  withdraw,
}

func withdraw(cmd *cobra.Command, args []string) error {
	url = "http://localhost:8080/users/" + strconv.Itoa(userID) + "/withdraw"
	requestBody := Request{
		Amount:     amount,
		EthAddress: ethAddress,
	}

	bytesObj, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	body := bytes.NewBuffer(bytesObj)
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Printf("%v was succesfuly withdrawn to %v\n", amount, ethAddress)

	return nil
}

var getDataCmd = &cobra.Command{
	Use:   "get",
	Short: "Get data",
	RunE: func(cmd *cobra.Command, args []string) error {
		url = "http://localhost:8080/users/" + strconv.Itoa(userID) + "/get-data"
		resp, err := http.Get(url)
		if err != nil {
			return err
		}

		err = json.NewDecoder(resp.Body).Decode(&userVisible)
		if err != nil {
			return err
		}

		fmt.Println(userVisible.UserID, userVisible.EthAddress, userVisible.Balance)

		return nil
	},
}

var checkBalanceCmd = &cobra.Command{
	Use:   "checkbalance",
	Short: "Check balance",
	RunE: func(cmd *cobra.Command, args []string) error {
		url = fmt.Sprintf("http://localhost:8080/users/%d/check-balance", userID)
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		err = json.NewDecoder(resp.Body).Decode(&userVisible.Balance)
		if err != nil {
			return err
		}

		fmt.Printf("Your current balance is %v\n", userVisible.Balance)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(createUserCmd)
	rootCmd.AddCommand(transferCmd)
	rootCmd.AddCommand(withdrawCmd)
	rootCmd.AddCommand(getDataCmd)
	rootCmd.AddCommand(checkBalanceCmd)
	transferCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	transferCmd.Flags().IntVarP(&amount, "amount", "a", 1, "Amount to transfer")
	transferCmd.Flags().IntVarP(&recipientID, "recipient", "r", 0, "Recipient ID")
	withdrawCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	withdrawCmd.Flags().StringVar(&ethAddress, "address", "", "Amount to withdraw")
	withdrawCmd.Flags().IntVarP(&amount, "amount", "a", 0, "Amount to withdraw")
	getDataCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	checkBalanceCmd.Flags().IntVar(&userID, "id", 0, "User ID")
	err := transferCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
	err = transferCmd.MarkFlagRequired("amount")
	if err != nil {
		fmt.Println(err)
	}
	err = transferCmd.MarkFlagRequired("recipient")
	if err != nil {
		fmt.Println(err)
	}
	err = withdrawCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
	err = withdrawCmd.MarkFlagRequired("address")
	if err != nil {
		fmt.Println(err)
	}
	err = withdrawCmd.MarkFlagRequired("amount")
	if err != nil {
		fmt.Println(err)
	}
	err = getDataCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
	err = checkBalanceCmd.MarkFlagRequired("id")
	if err != nil {
		fmt.Println(err)
	}
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		return
	}
}
