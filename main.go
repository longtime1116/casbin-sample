package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

func main() {
	// モデルの読み込み
	m, err := model.NewModelFromFile("rbac_model.conf")
	if err != nil {
		log.Fatalf("モデルの読み込みに失敗しました: %v", err)
	}

	// ポリシーのアダプターをファイルから作成
	a := fileadapter.NewAdapter("rbac_policy.csv")

	// Enforcerを作成
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		log.Fatalf("Enforcerの作成に失敗しました: %v", err)
	}

	// Enforcerのロード
	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("ポリシーの読み込みに失敗しました: %v", err)
	}

	// アクセスチェック
	checkAccess(e, "lh", "shipowner1/ship1/equipment1", "read")
	checkAccess(e, "lh", "shipowner1/ship1/equipment1", "write")
	fmt.Println("---- manufacture1はshipowner1のみアクセス可能")
	checkAccess(e, "manufacture1_manager", "shipowner1/ship1/equipment1", "write")
	checkAccess(e, "manufacture1_manager", "shipowner2/ship1/equipment1", "write")
	fmt.Println("---- manufacture2 は shipowner1 も shipowner2 もアクセス可能")
	checkAccess(e, "manufacture2_manager", "shipowner1/ship1/equipment1", "write")
	checkAccess(e, "manufacture2_manager", "shipowner2/ship1/equipment1", "write")
	fmt.Println("---- employeeはreadのみ")
	checkAccess(e, "manufacture1_employee", "shipowner1/ship1/equipment1", "read")
	checkAccess(e, "manufacture1_employee", "shipowner1/ship1/equipment1", "write")
}

// アクセスをチェックするヘルパー関数
func checkAccess(e *casbin.Enforcer, sub, obj, act string) {
	ok, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.Fatalf("Enforceの実行中にエラーが発生しました: %v", err)
	}

	if ok {
		fmt.Printf("⭕️許可: %s -> %s -> %s\n", sub, obj, act)
	} else {
		fmt.Printf("🙅‍拒否: %s -> %s -> %s\n", sub, obj, act)
	}
}
