using UnityEngine;

public class BlockController : MonoBehaviour
{
    [SerializeField] private Block[] blocks;
    [SerializeField] private GameObject blockPrefab;

    public delegate void OnBlockClicked(int row, int col);
    public OnBlockClicked OnBlockClickedDelegate;

    // 1. ��� Block�� �ʱ�ȭ
    public void InitBlocks()
    {
        float colStartPos = -12.6f;
        float rowStartPos = 12.6f;

        blocks = new Block[15 * 15];

        for (int i = 0; i < 15; i++)
        {
            for (int j = 0; j < 15; j++)
            {
                var blockObject = Instantiate(blockPrefab, transform);
                blockObject.transform.localPosition =
                    new Vector3(colStartPos + (1.8f * j), rowStartPos - (1.8f * i), 0);

                var blockIndex = i * 15 + j;

                Block block = blockObject.GetComponent<Block>();
                block.InitMarker(blockIndex, blockIndex =>
                {
                    // Ư�� Block�� Ŭ�� �� ���¿� ���� ó��
                    var row = blockIndex / Constants.BlockColumnCount;
                    var col = blockIndex % Constants.BlockColumnCount;
                    OnBlockClickedDelegate?.Invoke(row, col);
                });
                blocks[i * 15 + j] = block;
            }
        }
    }

    // 2. Ư�� Block�� ��Ŀ ǥ��
    public void PlaceMaker(Block.MarkerType markerType, int row, int col)
    {
        // row, col >> index ��ȯ
        var blockIndex = row * Constants.BlockColumnCount + col;
        blocks[blockIndex].SetMarker(markerType);
    }

    // 3. Ư�� Block�� ������ ����
    public void SetBlockColor()
    {
        // TODO: ���� ������ �ϼ��Ǹ� ����
    }
}