

using UnityEngine;

public class PlayerStateIdle : PlayerState, IPlayerState
{
    public PlayerStateIdle(PlayerController playerController, Animator animator)
        : base(playerController, animator) { }


    public void Enter()
    {
    }

    public void Update()
    {
    }

    public void Exit()
    {
    }
}