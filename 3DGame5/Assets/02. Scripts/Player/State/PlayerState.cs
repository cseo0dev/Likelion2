
using UnityEngine;

public class PlayerState
{
    protected PlayerController _playerController;
    protected Animator _animator;

    public PlayerState(PlayerController playerController, Animator animator)
    {
        _playerController = playerController;
        _animator = animator;
    }
}