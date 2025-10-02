using System;
using UnityEngine;

public class EllenPlayerController : PlayerController, IWeaponObserver<GameObject>
{
    [SerializeField] private Transform weaponAttachTransform; // 무기를 장착할 오브젝트 위치

    private MeleeController _meleeController;

    private void Start()
    {
        // 무기 장착
        var staffObject = Resources.Load<GameObject>("Staff"); // 리소스 폴더에 있는 Staff 프리팹 갖고오기
        _meleeController = Instantiate(staffObject, weaponAttachTransform).GetComponent<MeleeController>();
        _meleeController.Subscribe(this);
    }

    public void MeleeAttackStart()
    {
        _meleeController.StartTrigger();
    }

    public void MeleeAttackEnd()
    {
        _meleeController.EndTrigger();
    }

    public void OnNext(GameObject value)
    {
        // 무기가 충돌했을 때 충돌 대상 불러오기
        var enemyController = value.GetComponent<EnemyController>();
        if (enemyController)
        {
            // Enemy에게 데미지 가하기
            enemyController.SetHit(30, transform.forward); // 데미지, 방향
        }
    }

    public void OnCompleted()
    {
        // ex) 무기 내구도가 다 떨어졌을 때 구독을 취소하겠다.
        _meleeController.Unsubscribe(this);
    }

    public void OnError(Exception error)
    {

    }
}
