using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using static Constants;

[RequireComponent(typeof(Animator))]
[RequireComponent(typeof(PlayerInput))]
public class PlayerController : MonoBehaviour
{
    [SerializeField] private Transform headTransform;

    [Header("이동")] 
    [SerializeField] [Range(1, 5)] private float breakForce = 1f;

    [SerializeField] private float jumpHeight = 2f;
    
    public float BreakForce => breakForce;
    
    // 컴포넌트 캐싱
    private Animator _animator;
    private PlayerInput _playerInput;
    private CharacterController _characterController;
    
    // 상태 정보
    public EPlayerState State { get; private set; }
    private Dictionary<EPlayerState, ICharacterState> _states;
    
    // 캐릭터 이동 정보
    private float _velocityY;

    private void Awake()
    {
        // 컴포넌트 초기화
        _animator = GetComponent<Animator>();
        _playerInput = GetComponent<PlayerInput>();
        _characterController = GetComponent<CharacterController>();
        
        // 상태 객체 초기화
        var playerStateIdle = new PlayerStateIdle(this, _animator, _playerInput);
        var playerStateMove = new PlayerStateMove(this, _animator, _playerInput);
        var playerStateJump = new PlayerStateJump(this, _animator, _playerInput);
        var playerStateAttack = new PlayerStateAttack(this, _animator, _playerInput);
        var playerStateHit = new PlayerStateHit(this, _animator, _playerInput);
        
        _states = new Dictionary<EPlayerState, ICharacterState>
        {
            { EPlayerState.Idle, playerStateIdle },
            { EPlayerState.Move, playerStateMove },
            { EPlayerState.Jump, playerStateJump },
            { EPlayerState.Attack, playerStateAttack },
            { EPlayerState.Hit, playerStateHit },
        };

        // Cursor 숨기기
        _playerInput.actions["Cursor"].performed += _ => GameManager.Instance.SetCursorLock();
    }

    private void OnEnable()
    {
        // 카메라 초기화
        _playerInput.camera = Camera.main;
        if (_playerInput.camera != null)
        {
            _playerInput.camera.GetComponent<CameraController>().SetTarget(headTransform, _playerInput);
        }

        // 상태 초기화
        State = EPlayerState.None;
    }

    private void OnDisable()
    {
        
    }

    private void Update()
    {
        if (GameManager.Instance.GameState != EGameState.Play)
        {
            return;
        }

        if (State != EPlayerState.None)
        {
            _states[State].Update();
        }
    }

    // 새로운 상태를 할당하는 함수
    public void SetState(EPlayerState state)
    {
        if (State == state) return;
        if (State != EPlayerState.None) _states[State].Exit();
        State = state;
        if (State != EPlayerState.None) _states[State].Enter();
    }

    // 점프
    public void Jump()
    {
        if (!_characterController.isGrounded) return;
        _velocityY = Mathf.Sqrt(jumpHeight * -2f * Gravity);
    }

    // Hit
    public void SetHit(int damage, Vector3 attackDirection)
    {
        SetState(EPlayerState.Hit);
        _animator.SetFloat(PlayerAniParamHitX, attackDirection.x);
        _animator.SetFloat(PlayerAniParamHitZ, attackDirection.z);
    }

    private void OnAnimatorMove()
    {
        if (GameManager.Instance.GameState != EGameState.Play) return;

        Vector3 movePosition;
        if (_characterController.isGrounded)
        {
            movePosition = _animator.deltaPosition;            
        }
        else
        {
            movePosition = _characterController.velocity * Time.deltaTime;
        }
        
        _velocityY += Gravity * Time.deltaTime;
        movePosition.y = _velocityY * Time.deltaTime;
        _characterController.Move(movePosition);
    }
}
