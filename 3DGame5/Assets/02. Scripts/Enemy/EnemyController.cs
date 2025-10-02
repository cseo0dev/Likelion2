using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.AI;
using static Constants;

[RequireComponent(typeof(Animator))]
[RequireComponent(typeof(NavMeshAgent))]
public class EnemyController : MonoBehaviour
{
    [Header("AI")]
    [SerializeField] private float patrolWaitTime = 1f;
    [SerializeField] private float patrolChance = 30f;
    [SerializeField] private float patrolDetectionDistance = 10f;
    [SerializeField] private LayerMask detactionTargetLayerMask;
    [SerializeField] private float chaseWaitTime = 1f;
    [SerializeField] private float detectionSightAngle = 30f;
    [SerializeField] private float minimumRunDistance = 1f;
    [SerializeField] private float attackWaitTime = 0f;

    private Animator _animator;
    private NavMeshAgent _navMeshAgent;
    private Transform _targetTransform;

    // 상태 관리
    public EEnemyState State { get; private set; }
    private Dictionary<EEnemyState, ICharacterState> _states;

    // AI 관련
    public float PatrolWaitTime => patrolWaitTime;
    public float PatrolChance => patrolChance;
    public float PatrolDetectionDistance => patrolDetectionDistance;
    public float ChaseWaitTime => chaseWaitTime;
    public float DetectionSightAngle => detectionSightAngle;
    public float MinimumRunDistance => minimumRunDistance;
    public float AttackWaitTime => attackWaitTime;
    
    private Collider[] _detectionResults = new Collider[1]; // 배열로 선언한 이유 : OverlapSphereNonAlloc 해당 함수가 배열로 선언된 함수여서

    private void Awake()
    {
        _animator = GetComponent<Animator>();
        _navMeshAgent = GetComponent<NavMeshAgent>();

        // 플레이어 정보 초기화
        _targetTransform = null;

        // NavMeshAgent 설정
        _navMeshAgent.updatePosition = false;
        _navMeshAgent.updateRotation = true;

        // 상태 초기화
        var enemyStateIdle = new EnemyStateIdle(this, _animator, _navMeshAgent);
        var enemyStatePatrol = new EnemyStatePatrol(this, _animator, _navMeshAgent);
        var enemyStateChase = new EnemyStateChase(this, _animator, _navMeshAgent);
        var enemyStateAttack = new EnemyStateAttack(this, _animator, _navMeshAgent);
        var enemyStateHit = new EnemyStateHit(this, _animator, _navMeshAgent);

        _states = new Dictionary<EEnemyState, ICharacterState>
        {
            { EEnemyState.Idle, enemyStateIdle },
            { EEnemyState.Patrol, enemyStatePatrol },
            { EEnemyState.Chase, enemyStateChase },
            { EEnemyState.Attack, enemyStateAttack },
            { EEnemyState.Hit, enemyStateHit },
        };
        SetState(EEnemyState.Idle);
    }

    private void Update()
    {
        if (GameManager.Instance.GameState == EGameState.Pause)
        {
            SetState(EEnemyState.Idle);
        }

        if (State != EEnemyState.None)
        {
            _states[State].Update();
        }
    }

    public void SetState(EEnemyState state)
    {
        if (State == state) return;
        if (State != EEnemyState.None) _states[State].Exit();
        State = state;
        if (State != EEnemyState.None) _states[State].Enter();
    }

    // 공격 받았을 때 실행되는 함수
    public void SetHit(int damage, Vector3 attackDirection)
    {
        SetState(EEnemyState.Hit);
        StartCoroutine(Knockback(attackDirection));
    }

    // 넉백 구현
    private IEnumerator Knockback(Vector3 direction)
    {
        Vector3 knockbackDirection = direction; // 방향
        float knockbackDistance = 1f; // 거리
        float knockbackDuration = 0.2f; // 유지시간
        float elapsed = 0f; // Duration 검사용

        Vector3 startPosition = transform.position;
        Vector3 targetPosition = startPosition + knockbackDirection * knockbackDistance;
        targetPosition.y = transform.position.y; // y축 영향은 없도록 (위로 튀는 현상 방지)

        while (elapsed < knockbackDuration)
        {
            Vector3 lerpPosition = Vector3.Lerp(startPosition, targetPosition, elapsed / knockbackDuration);
            lerpPosition.y = startPosition.y;
            transform.position = lerpPosition;
            elapsed += Time.deltaTime;
            yield return null;
        }

        transform.position = targetPosition;
    }

    private void OnAnimatorMove()
    {
        var position = _animator.rootPosition;
        _navMeshAgent.nextPosition = position;
        transform.position = position;
    }

    // 일정 거리 안에 Player가 있는지 확인 후 있으면 반환
    // 있을 경우, 이미 찾은 상태면 기존 Player 반환
    // 없으면 null 반환
    public Transform DetectionTargetInCircle()
    {
        if (!_targetTransform)
        {
            Physics.OverlapSphereNonAlloc(transform.position,
                PatrolDetectionDistance, _detectionResults, detactionTargetLayerMask);
            _targetTransform = _detectionResults[0]?.transform;
        }
        else
        {
            float playerDistance = Vector3.Distance(transform.position, _targetTransform.position);
            if (playerDistance > PatrolDetectionDistance)
            {
                _targetTransform = null;
                _detectionResults[0] = null;
            }
        }
        return _targetTransform;
    }

    // 기즈모를 이용해서 목적지가 어디에 만들어졌는지 체크
    private void OnDrawGizmos()
    {
        // 감지 범위
        Gizmos.color = Color.yellow;
        Gizmos.DrawWireSphere(transform.position, PatrolDetectionDistance);

        // 시야각
        Gizmos.color = Color.red;
        Vector3 rightDirection = Quaternion.Euler(0, detectionSightAngle, 0) * transform.forward;
        Vector3 leftDirection = Quaternion.Euler(0, -detectionSightAngle, 0) * transform.forward;
        Gizmos.DrawRay(transform.position, rightDirection * PatrolDetectionDistance);
        Gizmos.DrawRay(transform.position, leftDirection * PatrolDetectionDistance);
        Gizmos.DrawRay(transform.position, transform.forward * PatrolDetectionDistance);

        // Agent 목적지 표시
        if (_navMeshAgent != null && _navMeshAgent.hasPath)
        {
            Gizmos.color = Color.green;
            Gizmos.DrawSphere(_navMeshAgent.destination, 0.5f);
            Gizmos.DrawLine(transform.position, _navMeshAgent.destination);
        }
    }
}
