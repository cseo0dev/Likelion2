using System;
using UnityEngine;

public class ChomperEnemyController : EnemyController, IWeaponObserver<GameObject>
{
    private MeleeController _meleeController;
    
    private void Start()
    {
        _meleeController = GetComponent<MeleeController>();
        _meleeController.Subscribe(this);
    }

    public void PlayStep() { }
    public void Grunt() { }

    public void AttackBegin()
    {
        _meleeController.StartTrigger();
    }

    public void AttackEnd()
    {
        _meleeController.EndTrigger();
    }

    public void OnNext(GameObject value)
    {
        var playerController = value.GetComponent<PlayerController>();
        if (playerController)
        {
            playerController.SetHit(10, -transform.forward);
        }
    }

    public void OnCompleted()
    {
        _meleeController.Unsubscribe(this);
    }

    public void OnError(Exception error)
    {

    }
}
